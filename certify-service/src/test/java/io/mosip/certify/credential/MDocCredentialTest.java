package io.mosip.certify.credential;

import io.mosip.kernel.signature.service.CoseSignatureService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.utils.MDocProcessor;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.service.SignatureService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive tests for MDocCredential
 * Tests cover:
 * - Format handling
 * - Credential creation workflow
 * - Proof generation with COSE signing
 * - Error handling and edge cases
 * - ISO 18013-5 compliance
 */
@RunWith(MockitoJUnitRunner.class)
public class MDocCredentialTest {

    private MDocCredential mDocCredential;

    @Mock
    private VCFormatter vcFormatter;

    @Mock
    private SignatureService signatureService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private MDocProcessor mDocProcessor;

    @Before
    public void setUp() {
        mDocCredential = new MDocCredential(vcFormatter, signatureService, mock(CoseSignatureService.class),
                objectMapper, mDocProcessor);
    }

    // ==================== Format Handling Tests ====================

    @Test
    public void should_returnTrue_when_canHandleMsoMdoc() {
        assertTrue("Should handle MSO_MDOC format",
                mDocCredential.canHandle(VCFormats.MSO_MDOC));
    }

    @Test
    public void should_returnFalse_when_canHandleOtherFormat() {
        assertFalse("Should not handle ldp_vc", mDocCredential.canHandle(VCFormats.LDP_VC));
        assertFalse("Should not handle dc+sd-jwt", mDocCredential.canHandle(VCFormats.DC_SD_JWT));
        assertFalse("Should not handle null", mDocCredential.canHandle(null));
    }

    // ==================== Credential Creation Tests ====================

    @Test
    public void should_createCredential_when_validInputProvided() throws Exception {
        String templateName = "mDocTemplate";
        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put("name", "John Doe");
        templateParams.put("age", 30);
        templateParams.put("didUrl", "https://issuer.example.com");

        String templatedJSON = "{\"docType\":\"org.iso.18013.5.1.mDL\",\"nameSpaces\":{}}";
        Map<String, Object> finalMDoc = new HashMap<>();
        finalMDoc.put("_docType", "org.iso.18013.5.1.mDL");
        finalMDoc.put("nameSpaces", new HashMap<>());
        String expectedResult = "{\"_docType\":\"org.iso.18013.5.1.mDL\",\"nameSpaces\":{}}";

        when(vcFormatter.format(templateParams)).thenReturn(templatedJSON);
        when(mDocProcessor.processTemplatedJson(eq(templatedJSON), eq(templateParams), any())).thenReturn(finalMDoc);
        when(objectMapper.writeValueAsString(finalMDoc)).thenReturn(expectedResult);

        String result = mDocCredential.createCredential(templateParams, templateName);

        assertNotNull("Result should not be null", result);
        assertEquals("Result should match expected JSON", expectedResult, result);

        verify(vcFormatter).format(templateParams);
        verify(mDocProcessor).processTemplatedJson(eq(templatedJSON), eq(templateParams), any());
        verify(objectMapper).writeValueAsString(finalMDoc);
    }

    @Test
    public void should_createCredential_when_complexTemplateProvided() throws Exception {
        String templateName = "complexTemplate";
        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put("familyName", "Doe");
        templateParams.put("givenName", "John");
        templateParams.put("birthDate", "1990-08-25");

        String templatedJSON = "{\"docType\":\"org.iso.18013.5.1.mDL\",\"nameSpaces\":{\"org.iso.18013.5.1\":[]}}";
        Map<String, Object> finalMDoc = new HashMap<>();
        finalMDoc.put("_docType", "org.iso.18013.5.1.mDL");
        Map<String, Object> nameSpaces = new HashMap<>();
        nameSpaces.put("org.iso.18013.5.1", new ArrayList<>());
        finalMDoc.put("nameSpaces", nameSpaces);

        when(vcFormatter.format(templateParams)).thenReturn(templatedJSON);
        when(mDocProcessor.processTemplatedJson(eq(templatedJSON), eq(templateParams), any())).thenReturn(finalMDoc);
        when(objectMapper.writeValueAsString(finalMDoc)).thenReturn("{}");

        String result = mDocCredential.createCredential(templateParams, templateName);

        assertNotNull("Result should not be null", result);
        verify(mDocProcessor).processTemplatedJson(eq(templatedJSON), eq(templateParams), any());
    }

    @Test(expected = CertifyException.class)
    public void should_throwException_when_formatterFails() {
        String templateName = "badTemplate";
        Map<String, Object> templateParams = new HashMap<>();

        when(vcFormatter.format(templateParams))
                .thenThrow(new RuntimeException("Formatting failed"));

        mDocCredential.createCredential(templateParams, templateName);
    }

    @Test
    public void should_keepTemplateProcessingErrorCode_when_processorRejectsTemplate() {
        Map<String, Object> templateParams = new HashMap<>();
        String templatedJSON = "{\"docType\":\"org.iso.18013.5.1.mDL\"}";

        when(vcFormatter.format(templateParams)).thenReturn(templatedJSON);
        when(mDocProcessor.processTemplatedJson(eq(templatedJSON), eq(templateParams), any()))
                .thenThrow(new CertifyException(ErrorConstants.MDOC_TEMPLATE_PROCESSING_FAILED, "literal validityInfo date"));

        CertifyException exception = assertThrows(CertifyException.class,
                () -> mDocCredential.createCredential(templateParams, "mDocTemplate"));
        assertEquals(ErrorConstants.MDOC_TEMPLATE_PROCESSING_FAILED, exception.getErrorCode());
    }

    @Test
    public void should_throwMdocCreationFailed_when_processingFails() {
        Map<String, Object> templateParams = new HashMap<>();
        String templatedJSON = "{\"docType\":\"org.iso.18013.5.1.mDL\"}";

        when(vcFormatter.format(templateParams)).thenReturn(templatedJSON);
        when(mDocProcessor.processTemplatedJson(eq(templatedJSON), eq(templateParams), any()))
                .thenThrow(new RuntimeException("Processing failed"));

        CertifyException exception = assertThrows(CertifyException.class,
                () -> mDocCredential.createCredential(templateParams, "mDocTemplate"));
        assertEquals("MDOC_CREATION_FAILED", exception.getErrorCode());
    }

    @Test
    public void should_passTheSigningCertificateNotBefore_when_credentialIsCreated() throws Exception {
        String templateName = "mDocTemplate";
        Map<String, Object> templateParams = new HashMap<>();
        String templatedJSON = "{\"docType\":\"org.iso.18013.5.1.mDL\",\"nameSpaces\":{}}";
        ZonedDateTime certificateNotBefore = ZonedDateTime.of(2026, 7, 20, 8, 30, 15, 0, ZoneOffset.UTC);
        Map<String, Object> finalMDoc = new HashMap<>();

        when(vcFormatter.format(templateParams)).thenReturn(templatedJSON);
        when(vcFormatter.getAppID(templateName)).thenReturn("CERTIFY_VC_SIGN_EC_R1");
        when(vcFormatter.getRefID(templateName)).thenReturn("EC_SECP256R1_SIGN");
        when(mDocProcessor.signingCertificateNotBefore("CERTIFY_VC_SIGN_EC_R1", "EC_SECP256R1_SIGN"))
                .thenReturn(certificateNotBefore);
        when(mDocProcessor.processTemplatedJson(templatedJSON, templateParams, certificateNotBefore)).thenReturn(finalMDoc);
        when(objectMapper.writeValueAsString(finalMDoc)).thenReturn("{}");

        assertEquals("{}", mDocCredential.createCredential(templateParams, templateName));
        verify(mDocProcessor).processTemplatedJson(templatedJSON, templateParams, certificateNotBefore);
    }

    @Test(expected = CertifyException.class)
    public void should_throwException_when_jsonSerializationFails() throws Exception {
        String templateName = "mDocTemplate";
        Map<String, Object> templateParams = new HashMap<>();
        String templatedJSON = "{\"docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> finalMDoc = new HashMap<>();

        when(vcFormatter.format(templateParams)).thenReturn(templatedJSON);
        when(mDocProcessor.processTemplatedJson(eq(templatedJSON), eq(templateParams), any())).thenReturn(finalMDoc);
        when(objectMapper.writeValueAsString(finalMDoc))
                .thenThrow(new RuntimeException("Serialization failed"));

        mDocCredential.createCredential(templateParams, templateName);
    }

    // ==================== Proof Generation Tests ====================

    @Test
    public void should_generateCorrectVCResult_when_addProofCalled() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\",\"nameSpaces\":{}}";
        String appID = "testApp";
        String refID = "testRef";
        String signAlgorithm = "ES256";
        String didUrl = "https://example.com/did";

        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
        Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();
        Map<String, Object> mso = createTestMSO();
        byte[] signedMSO = new byte[]{1, 2, 3, 4};
        Map<String, Object> issuerSigned = createTestIssuerSigned();
        byte[] cborIssuerSigned = new byte[]{5, 6, 7, 8};

        try (MockedStatic<MDocProcessor> mockedStatic = mockStatic(MDocProcessor.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            when(mDocProcessor.getDigestAlgorithm()).thenReturn("SHA-384");
            mockedStatic.when(() -> MDocProcessor.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocProcessor.calculateDigests(eq(saltedNamespaces), any(), any()))
                    .thenReturn(taggedNamespaces);
            when(mDocProcessor.createMobileSecurityObject(eq(mDocJson), any()))
                    .thenReturn(mso);
            when(mDocProcessor.signMSO(mso, appID, refID, signAlgorithm))
                    .thenReturn(signedMSO);
            mockedStatic.when(() -> MDocProcessor.createIssuerSignedStructure(taggedNamespaces, signedMSO))
                    .thenReturn(issuerSigned);
            mockedStatic.when(() -> MDocProcessor.encodeToCBOR(any()))
                    .thenReturn(cborIssuerSigned);

            VCResult<?> result = mDocCredential.addProof(
                    vcToSign, null, signAlgorithm, appID, refID, didUrl, "Ed25519Signature2020"
            );

            assertNotNull("Result should not be null", result);
            assertEquals("Format should be MSO_MDOC", VCFormats.MSO_MDOC, result.getFormat());
            assertNotNull("Credential should not be null", result.getCredential());
            assertTrue("Credential should be a String", result.getCredential() instanceof String);

            verify(mDocProcessor).createMobileSecurityObject(eq(mDocJson), any());
            verify(mDocProcessor).signMSO(mso, appID, refID, signAlgorithm);
            // The value digests use the configured algorithm, the one written into the MSO
            mockedStatic.verify(() -> MDocProcessor.calculateDigests(eq(saltedNamespaces), any(), eq("SHA-384")));
            // Issuer signed is CBOR encoded and base64 url encoded
            mockedStatic.verify(() -> MDocProcessor.encodeToCBOR(issuerSigned));
            byte[] decodedMdoc = Base64.getUrlDecoder().decode(result.getCredential().toString());
            assertArrayEquals(decodedMdoc, cborIssuerSigned);
        }
    }

    @Test
    public void should_returnBase64UrlEncodedCredential_when_addProofCalled() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
        Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();
        Map<String, Object> mso = createTestMSO();
        byte[] signedMSO = new byte[]{1, 2, 3};
        Map<String, Object> issuerSigned = createTestIssuerSigned();
        byte[] cborIssuerSigned = "test data for base64url encoding".getBytes();

        try (MockedStatic<MDocProcessor> mockedStatic = mockStatic(MDocProcessor.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocProcessor.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocProcessor.calculateDigests(eq(saltedNamespaces), any(), any()))
                    .thenReturn(taggedNamespaces);
            when(mDocProcessor.createMobileSecurityObject(eq(mDocJson), any())).thenReturn(mso);
            when(mDocProcessor.signMSO(eq(mso), anyString(), anyString(), anyString()))
                    .thenReturn(signedMSO);
            mockedStatic.when(() -> MDocProcessor.createIssuerSignedStructure(any(), any()))
                    .thenReturn(issuerSigned);
            mockedStatic.when(() -> MDocProcessor.encodeToCBOR(any())).thenReturn(cborIssuerSigned);

            VCResult<?> result = mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );

            assertNotNull("Credential should not be null", result.getCredential());
            String credential = (String) result.getCredential();

            // Verify it's Base64 URL encoded (no +, /, or = padding)
            assertFalse("Should not contain +", credential.contains("+"));
            assertFalse("Should not contain /", credential.contains("/"));
            assertFalse("Should not contain = padding", credential.contains("="));
        }
    }

    @Test
    public void should_handleDifferentSignatureAlgorithms_when_addProofCalled() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        String[] algorithms = {"ES256", "ES384", "ES512"};

        for (String algorithm : algorithms) {
            Map<String, Object> mDocJson = createTestMDocJson();
            Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
            Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();
            Map<String, Object> mso = createTestMSO();
            byte[] signedMSO = new byte[]{1, 2, 3};
            Map<String, Object> issuerSigned = createTestIssuerSigned();
            byte[] cborIssuerSigned = new byte[]{4, 5, 6};

            try (MockedStatic<MDocProcessor> mockedStatic = mockStatic(MDocProcessor.class)) {
                when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
                mockedStatic.when(() -> MDocProcessor.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
                mockedStatic.when(() -> MDocProcessor.calculateDigests(eq(saltedNamespaces), any(), any()))
                        .thenReturn(taggedNamespaces);
                when(mDocProcessor.createMobileSecurityObject(eq(mDocJson), any())).thenReturn(mso);
                when(mDocProcessor.signMSO(eq(mso), anyString(), anyString(), eq(algorithm)))
                        .thenReturn(signedMSO);
                mockedStatic.when(() -> MDocProcessor.createIssuerSignedStructure(any(), any()))
                        .thenReturn(issuerSigned);
                mockedStatic.when(() -> MDocProcessor.encodeToCBOR(any())).thenReturn(cborIssuerSigned);

                VCResult<?> result = mDocCredential.addProof(
                        vcToSign, null, algorithm, "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
                );

                assertNotNull("Result should not be null for " + algorithm, result);
                assertEquals("Format should be MSO_MDOC", VCFormats.MSO_MDOC, result.getFormat());
            }
        }
    }

    @Test
    public void should_handleNullHeaders_when_addProofCalled() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
        Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();
        Map<String, Object> mso = createTestMSO();
        byte[] signedMSO = new byte[]{1, 2, 3};
        Map<String, Object> issuerSigned = createTestIssuerSigned();
        byte[] cborIssuerSigned = new byte[]{4, 5, 6};

        try (MockedStatic<MDocProcessor> mockedStatic = mockStatic(MDocProcessor.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocProcessor.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocProcessor.calculateDigests(eq(saltedNamespaces), any(), any()))
                    .thenReturn(taggedNamespaces);
            when(mDocProcessor.createMobileSecurityObject(eq(mDocJson), any())).thenReturn(mso);
            when(mDocProcessor.signMSO(eq(mso), anyString(), anyString(), anyString()))
                    .thenReturn(signedMSO);
            mockedStatic.when(() -> MDocProcessor.createIssuerSignedStructure(any(), any()))
                    .thenReturn(issuerSigned);
            mockedStatic.when(() -> MDocProcessor.encodeToCBOR(any())).thenReturn(cborIssuerSigned);

            VCResult<?> result = mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );

            assertNotNull("Result should not be null", result);
            assertEquals("Format should be MSO_MDOC", VCFormats.MSO_MDOC, result.getFormat());
        }
    }

    // ==================== Error Handling Tests ====================

    @Test(expected = CertifyException.class)
    public void should_throwException_when_jsonParsingFails() throws Exception {
        String vcToSign = "invalid json";
        String appID = "testApp";
        String refID = "testRef";

        when(objectMapper.readValue(vcToSign, Map.class))
                .thenThrow(new RuntimeException("JSON parsing failed"));

        mDocCredential.addProof(
                vcToSign, null, "ES256", appID, refID, "https://example.com/did", "Ed25519Signature2020"
        );
    }

    @Test(expected = CertifyException.class)
    public void should_throwException_when_saltingFails() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();

        try (MockedStatic<MDocProcessor> mockedStatic = mockStatic(MDocProcessor.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocProcessor.addRandomSalts(mDocJson))
                    .thenThrow(new RuntimeException("Salting failed"));

            mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );
        }
    }

    @Test(expected = CertifyException.class)
    public void should_throwException_when_digestCalculationFails() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();

        try (MockedStatic<MDocProcessor> mockedStatic = mockStatic(MDocProcessor.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocProcessor.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocProcessor.calculateDigests(eq(saltedNamespaces), any(), any()))
                    .thenThrow(new RuntimeException("Digest calculation failed"));

            mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );
        }
    }

    @Test(expected = CertifyException.class)
    public void should_throwException_when_msoCreationFails() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
        Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();

        try (MockedStatic<MDocProcessor> mockedStatic = mockStatic(MDocProcessor.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocProcessor.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocProcessor.calculateDigests(eq(saltedNamespaces), any(), any()))
                    .thenReturn(taggedNamespaces);
            when(mDocProcessor.createMobileSecurityObject(any(), any()))
                    .thenThrow(new RuntimeException("MSO creation failed"));

            mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );
        }
    }

    @Test(expected = CertifyException.class)
    public void should_throwException_when_msoSigningFails() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
        Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();
        Map<String, Object> mso = createTestMSO();

        try (MockedStatic<MDocProcessor> mockedStatic = mockStatic(MDocProcessor.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocProcessor.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocProcessor.calculateDigests(eq(saltedNamespaces), any(), any()))
                    .thenReturn(taggedNamespaces);
            when(mDocProcessor.createMobileSecurityObject(any(), any())).thenReturn(mso);
            when(mDocProcessor.signMSO(any(), anyString(), anyString(), anyString()))
                    .thenThrow(new RuntimeException("MSO signing failed"));

            mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );
        }
    }

    @Test(expected = CertifyException.class)
    public void should_throwException_when_cborEncodingFails() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
        Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();
        Map<String, Object> mso = createTestMSO();
        byte[] signedMSO = new byte[]{1, 2, 3};
        Map<String, Object> issuerSigned = createTestIssuerSigned();

        try (MockedStatic<MDocProcessor> mockedStatic = mockStatic(MDocProcessor.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocProcessor.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocProcessor.calculateDigests(eq(saltedNamespaces), any(), any()))
                    .thenReturn(taggedNamespaces);
            when(mDocProcessor.createMobileSecurityObject(any(), any())).thenReturn(mso);
            when(mDocProcessor.signMSO(any(), anyString(), anyString(), anyString()))
                    .thenReturn(signedMSO);
            mockedStatic.when(() -> MDocProcessor.createIssuerSignedStructure(any(), any()))
                    .thenReturn(issuerSigned);
            mockedStatic.when(() -> MDocProcessor.encodeToCBOR(any()))
                    .thenThrow(new RuntimeException("CBOR encoding failed"));

            mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );
        }
    }

    @Test(expected = CertifyException.class)
    public void should_throwException_when_issuerSignedStructureFails() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
        Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();
        Map<String, Object> mso = createTestMSO();
        byte[] signedMSO = new byte[]{1, 2, 3};

        try (MockedStatic<MDocProcessor> mockedStatic = mockStatic(MDocProcessor.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocProcessor.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocProcessor.calculateDigests(eq(saltedNamespaces), any(), any()))
                    .thenReturn(taggedNamespaces);
            when(mDocProcessor.createMobileSecurityObject(any(), any())).thenReturn(mso);
            when(mDocProcessor.signMSO(any(), anyString(), anyString(), anyString()))
                    .thenReturn(signedMSO);
            mockedStatic.when(() -> MDocProcessor.createIssuerSignedStructure(any(), any()))
                    .thenThrow(new RuntimeException("IssuerSigned structure creation failed"));

            mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );
        }
    }

    // ==================== Helper Methods ====================

    private Map<String, Object> createTestMDocJson() {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.iso.18013.5.1.mDL");
        mDocJson.put("nameSpaces", new HashMap<>());
        return mDocJson;
    }

    private Map<String, Object> createTestSaltedNamespaces() {
        Map<String, Object> saltedNamespaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();

        Map<String, Object> element = new HashMap<>();
        element.put("digestID", 0);
        element.put("elementIdentifier", "family_name");
        element.put("elementValue", "Doe");
        element.put("random", new byte[24]);
        elements.add(element);

        saltedNamespaces.put("org.iso.18013.5.1", elements);
        return saltedNamespaces;
    }

    private Map<String, Object> createTestTaggedNamespaces() {
        Map<String, Object> taggedNamespaces = new HashMap<>();
        taggedNamespaces.put("org.iso.18013.5.1", new ArrayList<>());
        return taggedNamespaces;
    }

    private Map<String, Object> createTestMSO() {
        Map<String, Object> mso = new HashMap<>();
        mso.put("version", "1.0");
        mso.put("digestAlgorithm", "SHA-256");
        mso.put("docType", "org.iso.18013.5.1.mDL");
        mso.put("valueDigests", new HashMap<>());
        mso.put("deviceKeyInfo", new HashMap<>());
        return mso;
    }

    private Map<String, Object> createTestIssuerSigned() {
        Map<String, Object> issuerSigned = new HashMap<>();
        issuerSigned.put("nameSpaces", new HashMap<>());
        issuerSigned.put("issuerAuth", new byte[]{1, 2, 3});
        return issuerSigned;
    }
}
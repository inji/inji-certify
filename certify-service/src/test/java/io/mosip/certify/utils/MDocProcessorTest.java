package io.mosip.certify.utils;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.mosip.certify.config.MDocConfig;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.signature.dto.CoseSignRequestDto;
import io.mosip.kernel.signature.dto.CoseSignResponseDto;
import io.mosip.kernel.signature.service.CoseSignatureService;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.ZonedDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive unit tests for MDocUtils covering:
 * - Template processing and data mapping
 * - Random salt generation
 * - Digest calculation and verification
 * - MSO structure generation per ISO 18013-5
 * - CBOR encoding/decoding
 * - DeviceKeyInfo handling
 * - COSE_Sign1 signing
 * - Date handling with CBOR tag 1004
 * - Error handling and edge cases
 */
@RunWith(MockitoJUnitRunner.class)
public class MDocProcessorTest {

    private static final ZonedDateTime FIXED_NOW = ZonedDateTime.of(2026, 7, 20, 10, 0, 0, 0, ZoneOffset.UTC);
    /** The notBefore of a signing certificate generated well before the issuance day. */
    private static final ZonedDateTime CERT_NOT_BEFORE = ZonedDateTime.of(2026, 1, 1, 9, 15, 0, 0, ZoneOffset.UTC);
    private static final Map<String, Map<String, ? extends Serializable>> expectedValidityInfo = Map.of(
            "signed", Map.of(
                    Constants.__CBOR_TAG, 0,
                    Constants.__CBOR_VALUE, "2026-07-20T00:00:00Z"
            ),
            "validFrom", Map.of(
                    Constants.__CBOR_TAG, 0,
                    Constants.__CBOR_VALUE, "2026-07-20T00:00:00Z"
            ),
            "validUntil", Map.of(
                    Constants.__CBOR_TAG, 0,
                    Constants.__CBOR_VALUE, "2031-07-20T00:00:00Z"
            )
    );

    @Mock
    private MDocConfig mDocConfig;

    @Mock
    private CoseSignatureService coseSignatureService;

    @Mock
    private KeymanagerService keymanagerService;

    private MDocProcessor mDocProcessor;

    private ObjectMapper objectMapper;

    @Before
    public void setUp() {
        objectMapper = new ObjectMapper();
        mDocProcessor = processorAt(FIXED_NOW);

        // Setup default mock behavior
        when(mDocConfig.getValidityPeriodYears()).thenReturn(5);
        when(mDocConfig.getMsoVersion()).thenReturn("1.0");
    }

    /** An MDocProcessor whose clock is fixed at the given time. */
    private MDocProcessor processorAt(ZonedDateTime now) {
        return new MDocProcessor(objectMapper, mDocConfig, coseSignatureService, keymanagerService,
                Clock.fixed(now.toInstant(), ZoneOffset.UTC));
    }

    // ==================== Template Processing Tests ====================

    @Test
    public void should_mapToISO18013Elements_when_validmDLTemplateIsProcessed() {
        String templatedJSON = withMandatoryMdlElements(createFullmDLTemplate());

        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put("didUrl", "https://issuer.example.com/did");
        templateParams.put("_holderId", "did:jwk:test123");

        Map<String, Object> result = mDocProcessor.processTemplatedJson(templatedJSON, templateParams, CERT_NOT_BEFORE);

        assertNotNull("Result should not be null", result);
        assertEquals("DocType should match", "org.iso.18013.5.1.mDL", result.get("_docType"));
        assertEquals("HolderId should match", "did:jwk:test123", result.get("_holderId"));
        assertEquals("Issuer should match", "https://issuer.example.com/did", result.get("_issuer"));

        Map<String, Object> nameSpaces = (Map<String, Object>) result.get("nameSpaces");
        assertNotNull("NameSpaces should not be null", nameSpaces);

        List<Map<String, Object>> items = (List<Map<String, Object>>) nameSpaces.get("org.iso.18013.5.1");
        assertEquals("the template's 3 elements plus the other mandatory ones", MdlDataElements.MANDATORY.size(), items.size());

        assertEquals("family_name", items.getFirst().get("elementIdentifier"));
        assertEquals("Doe", items.getFirst().get("elementValue"));
        // the template's digestIDs are replaced by random ones, unique within the namespace
        assertEquals(items.size(), items.stream().map(item -> item.get("digestID")).distinct().count());
        items.forEach(item -> assertTrue((Integer) item.get("digestID") >= 0));

        assertEquals("ValidityInfo should match", expectedValidityInfo, result.get("validityInfo"));
    }

    @Test
    public void processTemplatedJson_ValidityInfoPlaceholders_ReplacedWithTimestamps() {
        String templatedJSON = "{"
                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                + "\"validityInfo\": {"
                + "  \"validFrom\": \"${_validFrom}\","
                + "  \"validUntil\": \"${_validUntil}\","
                + "  \"signed\": \"${_signed}\""
                + "},"
                + "\"nameSpaces\": {}"
                + "}";

        Map<String, Object> result = mDocProcessor.processTemplatedJson(withMandatoryMdlElements(templatedJSON), new HashMap<>(), CERT_NOT_BEFORE);

        Map<String, Object> validityInfo = (Map<String, Object>) result.get("validityInfo");
        assertNotNull("ValidityInfo should not be null", validityInfo);

        String validFrom =  (String)((Map<String,Object>) validityInfo.get(VCDM2Constants.VALID_FROM)).get(Constants.__CBOR_VALUE);
        String validUntil =  (String)((Map<String,Object>) validityInfo.get(VCDM2Constants.VALID_UNTIL)).get(Constants.__CBOR_VALUE);
        String signed =  (String)((Map<String,Object>) validityInfo.get(Constants.SIGNED)).get(Constants.__CBOR_VALUE);

        assertNotNull("ValidFrom should be set", validFrom);
        assertNotNull("ValidUntil should be set", validUntil);
        assertNotEquals("${_validFrom}", validFrom);
        assertNotEquals("${_signed}", signed);
        assertNotEquals("${_validUntil}", validUntil);

        // ISO/IEC 18013-5: whole seconds, UTC offset written as "Z"
        String validityInfoTimestamp = "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z";
        assertTrue("ValidFrom should be whole seconds in UTC: " + validFrom, validFrom.matches(validityInfoTimestamp));
        assertTrue("Signed should be whole seconds in UTC: " + signed, signed.matches(validityInfoTimestamp));
        assertTrue("ValidUntil should be whole seconds in UTC: " + validUntil, validUntil.matches(validityInfoTimestamp));
    }

    @Test
    public void should_dropFractionsOfSeconds_when_clockHasSubSecondPrecision() {
        ZonedDateTime justBeforeNextSecond = FIXED_NOW.withNano(999_999_999);
        String templatedJSON = "{\"docType\": \"org.iso.18013.5.1.mDL\","
                + "\"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\", \"signed\": \"${_signed}\"},"
                + "\"nameSpaces\": {}}";

        Map<String, Object> result = processorAt(justBeforeNextSecond)
                .processTemplatedJson(withMandatoryMdlElements(templatedJSON), new HashMap<>(), CERT_NOT_BEFORE);

        // Truncated, not rounded up to the next second
        assertEquals(expectedValidityInfo, result.get("validityInfo"));
    }

    @Test
    public void should_giveTheSameTimestamps_when_twoMdlsAreIssuedOnTheSameUtcDay() {
        // ISO/IEC 18013-5, 9.1.2.4: the timestamps must not link the mDLs issued on one day
        String templatedJSON = "{\"docType\": \"org.iso.18013.5.1.mDL\","
                + "\"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\", \"signed\": \"${_signed}\"},"
                + "\"nameSpaces\": {}}";
        ZonedDateTime justAfterMidnight = FIXED_NOW.withHour(0).withSecond(1);
        ZonedDateTime justBeforeMidnight = FIXED_NOW.withHour(23).withMinute(59).withSecond(59);

        Object morning = processorAt(justAfterMidnight)
                .processTemplatedJson(withMandatoryMdlElements(templatedJSON), new HashMap<>(), CERT_NOT_BEFORE).get("validityInfo");
        Object night = processorAt(justBeforeMidnight)
                .processTemplatedJson(withMandatoryMdlElements(templatedJSON), new HashMap<>(), CERT_NOT_BEFORE).get("validityInfo");

        assertEquals(expectedValidityInfo, morning);
        assertEquals(expectedValidityInfo, night);
    }

    @Test
    public void should_startValidFromOnTheIssueDate_when_issueDateIsAfterTheIssuanceDay() {
        Map<String, Object> validityInfo = (Map<String, Object>) mDocProcessor
                .processTemplatedJson(mdlTemplateWithIssueDate("2026-08-01"), new HashMap<>(), CERT_NOT_BEFORE).get("validityInfo");

        assertEquals("2026-07-20T00:00:00Z", cborValue(validityInfo, "signed"));
        assertEquals("2026-08-01T00:00:00Z", cborValue(validityInfo, "validFrom"));
        assertEquals("2031-08-01T00:00:00Z", cborValue(validityInfo, "validUntil"));
    }

    @Test
    public void should_startValidFromOnTheIssuanceDay_when_issueDateIsEarlier() {
        Object validityInfo = mDocProcessor
                .processTemplatedJson(mdlTemplateWithIssueDate("2024-06-15"), new HashMap<>(), CERT_NOT_BEFORE).get("validityInfo");

        assertEquals(expectedValidityInfo, validityInfo);
    }

    @Test
    public void should_startValidFromOnTheIssueDate_when_templateTagsTheIssueDateAsAFullDate() {
        String template = mdlTemplateWithIssueDate("2026-08-01").replace("\"2026-08-01\"",
                "{\"__cbor_tag\": 1004, \"__cbor_value\": \"2026-08-01\"}");
        Map<String, Object> validityInfo = (Map<String, Object>) mDocProcessor
                .processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE).get("validityInfo");

        assertEquals("2026-07-20T00:00:00Z", cborValue(validityInfo, "signed"));
        assertEquals("2026-08-01T00:00:00Z", cborValue(validityInfo, "validFrom"));
        assertEquals("2031-08-01T00:00:00Z", cborValue(validityInfo, "validUntil"));
    }

    @Test
    public void should_notSignBeforeTheSigningCertificate_when_certificateStartedEarlierOnTheIssuanceDay() {
        // ISO/IEC 18013-5, 9.3.1: signed must fall within the validity of the certificate in the MSO
        // header. The certificate starts at 08:30:15Z on the issuance day, after 00:00:00Z.
        ZonedDateTime certificateNotBefore = FIXED_NOW.withHour(8).withMinute(30).withSecond(15);
        Map<String, Object> validityInfo = (Map<String, Object>) mDocProcessor
                .processTemplatedJson(mdlTemplateWithIssueDate("2024-06-15"), new HashMap<>(), certificateNotBefore)
                .get("validityInfo");

        assertEquals("2026-07-20T08:30:15Z", cborValue(validityInfo, "signed"));
        assertEquals("2026-07-20T08:30:15Z", cborValue(validityInfo, "validFrom"));
        assertEquals("2031-07-20T08:30:15Z", cborValue(validityInfo, "validUntil"));
    }

    @Test
    public void should_giveTheSameTimestamps_when_twoMdlsAreSignedWithANewCertificateOnTheSameDay() {
        // On the day the certificate starts, every mDL signed with it still shares one value
        ZonedDateTime certificateNotBefore = FIXED_NOW.withHour(8).withMinute(30).withSecond(15);
        ZonedDateTime soonAfter = FIXED_NOW.withHour(8).withMinute(31);
        ZonedDateTime justBeforeMidnight = FIXED_NOW.withHour(23).withMinute(59).withSecond(59);

        Object first = processorAt(soonAfter).processTemplatedJson(mdlTemplateWithIssueDate("2024-06-15"),
                new HashMap<>(), certificateNotBefore).get("validityInfo");
        Object second = processorAt(justBeforeMidnight).processTemplatedJson(mdlTemplateWithIssueDate("2024-06-15"),
                new HashMap<>(), certificateNotBefore).get("validityInfo");

        assertEquals(first, second);
    }

    @Test
    public void should_startValidFromOnTheIssueDate_when_issueDateIsAfterTheSigningCertificateStart() {
        ZonedDateTime certificateNotBefore = FIXED_NOW.withHour(8).withMinute(30).withSecond(15);
        Map<String, Object> validityInfo = (Map<String, Object>) mDocProcessor
                .processTemplatedJson(mdlTemplateWithIssueDate("2026-08-01"), new HashMap<>(), certificateNotBefore)
                .get("validityInfo");

        assertEquals("2026-07-20T08:30:15Z", cborValue(validityInfo, "signed"));
        assertEquals("2026-08-01T00:00:00Z", cborValue(validityInfo, "validFrom"));
        assertEquals("2031-08-01T00:00:00Z", cborValue(validityInfo, "validUntil"));
    }

    @Test
    public void should_returnTheCertificateNotBefore_when_keymanagerReturnsTheSigningCertificate() throws Exception {
        ZonedDateTime notBefore = ZonedDateTime.of(2026, 7, 20, 8, 30, 15, 0, ZoneOffset.UTC);
        KeyPairGenerateResponseDto certificate = new KeyPairGenerateResponseDto();
        certificate.setCertificate(selfSignedCertificatePem(notBefore));
        when(keymanagerService.getCertificate("CERTIFY_VC_SIGN_EC_R1", Optional.of("EC_SECP256R1_SIGN")))
                .thenReturn(certificate);

        assertEquals(notBefore, mDocProcessor.signingCertificateNotBefore("CERTIFY_VC_SIGN_EC_R1", "EC_SECP256R1_SIGN"));
    }

    @Test
    public void should_reject_when_signedIsBeforeTheCertificateInTheMsoHeader() throws Exception {
        // the key was rotated after signed was set: x5chain now starts at 08:30:15Z
        byte[] signedMSO = coseSign1With(new ByteString(
                selfSignedCertificateDer(ZonedDateTime.of(2026, 7, 20, 8, 30, 15, 0, ZoneOffset.UTC))));

        Exception exception = assertThrows(IllegalStateException.class,
                () -> MDocProcessor.requireSignedWithinCertificate(msoSignedAt("2026-07-20T00:00:00Z"), signedMSO));
        assertEquals("validityInfo.signed 2026-07-20T00:00:00Z is outside the validity of the certificate in the MSO header",
                exception.getMessage());
    }

    @Test
    public void should_accept_when_signedIsWithinTheCertificateInTheMsoHeader() throws Exception {
        byte[] der = selfSignedCertificateDer(CERT_NOT_BEFORE);
        Array chain = new Array();
        chain.add(new ByteString(der));

        // x5chain is a single certificate or an array with the leaf first
        MDocProcessor.requireSignedWithinCertificate(msoSignedAt("2026-07-20T00:00:00Z"), coseSign1With(new ByteString(der)));
        MDocProcessor.requireSignedWithinCertificate(msoSignedAt("2026-07-20T00:00:00Z"), coseSign1With(chain));
    }

    @Test
    public void should_startValidFromTheNextDay_when_issueDateIsADateTimeAfterTheIssuanceDay() {
        // Table 5 allows a tdate issue_date; validFrom keeps day precision, so it is the next 00:00:00Z
        Map<String, Object> validityInfo = (Map<String, Object>) mDocProcessor
                .processTemplatedJson(mdlTemplateWithIssueDate("2026-08-01T10:00:00Z"), new HashMap<>(), CERT_NOT_BEFORE)
                .get("validityInfo");

        assertEquals("2026-07-20T00:00:00Z", cborValue(validityInfo, "signed"));
        assertEquals("2026-08-02T00:00:00Z", cborValue(validityInfo, "validFrom"));
        assertEquals("2031-08-02T00:00:00Z", cborValue(validityInfo, "validUntil"));
    }

    @Test
    public void should_startValidFromOnTheIssueDate_when_issueDateIsADateTimeAtMidnight() {
        Map<String, Object> validityInfo = (Map<String, Object>) mDocProcessor
                .processTemplatedJson(mdlTemplateWithIssueDate("2026-08-01T02:00:00+02:00"), new HashMap<>(), CERT_NOT_BEFORE)
                .get("validityInfo");

        assertEquals("2026-08-01T00:00:00Z", cborValue(validityInfo, "validFrom"));
    }

    @Test
    public void should_startValidFromTheNextDay_when_issueDateIsAFractionOfASecondAfterMidnight() {
        Map<String, Object> validityInfo = (Map<String, Object>) mDocProcessor
                .processTemplatedJson(mdlTemplateWithIssueDate("2026-08-01T00:00:00.500Z"), new HashMap<>(), CERT_NOT_BEFORE)
                .get("validityInfo");

        assertEquals("2026-08-02T00:00:00Z", cborValue(validityInfo, "validFrom"));
    }

    @Test
    public void should_startValidFromTheNextDay_when_templateTagsTheIssueDateAsATdate() {
        String template = mdlTemplateWithIssueDate("2026-08-01T10:00:00Z").replace("\"2026-08-01T10:00:00Z\"",
                "{\"__cbor_tag\": 0, \"__cbor_value\": \"2026-08-01T10:00:00Z\"}");
        Map<String, Object> validityInfo = (Map<String, Object>) mDocProcessor
                .processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE).get("validityInfo");

        assertEquals("2026-08-02T00:00:00Z", cborValue(validityInfo, "validFrom"));
    }

    private static String selfSignedCertificatePem(ZonedDateTime notBefore) throws Exception {
        byte[] der = selfSignedCertificateDer(notBefore);
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END CERTIFICATE-----\n";
    }

    private static byte[] selfSignedCertificateDer(ZonedDateTime notBefore) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair keyPair = generator.generateKeyPair();
        X500Name subject = new X500Name("CN=Test Document Signer");
        return new JcaX509v3CertificateBuilder(subject, BigInteger.ONE, Date.from(notBefore.toInstant()),
                Date.from(notBefore.plusYears(1).toInstant()), subject, keyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate()))
                .getEncoded();
    }

    /** A COSE_Sign1 whose unprotected header carries x5chain (label 33). */
    private static byte[] coseSign1With(DataItem x5chain) throws Exception {
        co.nstant.in.cbor.model.Map unprotectedHeader = new co.nstant.in.cbor.model.Map();
        unprotectedHeader.put(new UnsignedInteger(33), x5chain);
        Array cose = new Array();
        cose.add(new ByteString(new byte[0]));
        cose.add(unprotectedHeader);
        cose.add(new ByteString(new byte[]{1}));
        cose.add(new ByteString(new byte[]{2}));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        new CborEncoder(out).encode(cose);
        return out.toByteArray();
    }

    private static Map<String, Object> msoSignedAt(String signed) {
        return Map.of(Constants.VALIDITY_INFO,
                Map.of(Constants.SIGNED, Map.of(Constants.__CBOR_TAG, 0, Constants.__CBOR_VALUE, signed)));
    }

    private static String mdlTemplateWithIssueDate(String issueDate) {
        return withMandatoryMdlElements("{\"docType\": \"org.iso.18013.5.1.mDL\","
                + "\"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\", \"signed\": \"${_signed}\"},"
                + "\"nameSpaces\": {\"org.iso.18013.5.1\": ["
                + "{\"elementIdentifier\": \"issue_date\", \"elementValue\": \"" + issueDate + "\"}]}}");
    }

    private static String mdlTemplateWithPortrait(String portrait) {
        return "{\"docType\": \"org.iso.18013.5.1.mDL\","
                + "\"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\", \"signed\": \"${_signed}\"},"
                + "\"nameSpaces\": {\"org.iso.18013.5.1\": ["
                + "{\"elementIdentifier\": \"portrait\", \"elementValue\": \"" + portrait + "\"}]}}";
    }

    /** Sample values for the mandatory elements a test template leaves out. */
    private static final Map<String, Object> MANDATORY_SAMPLE_VALUES = Map.ofEntries(
            Map.entry("family_name", "Doe"), Map.entry("given_name", "John"),
            Map.entry("birth_date", "1990-08-25"),
            // before FIXED_NOW, so it doesn't move validFrom
            Map.entry("issue_date", "2024-06-15"), Map.entry("expiry_date", "2031-06-15"),
            Map.entry("issuing_country", "IN"), Map.entry("issuing_authority", "Test Authority"),
            Map.entry("document_number", "D1"), Map.entry("portrait", "/9j/4A"), // a JPEG header
            Map.entry("driving_privileges", List.of()), Map.entry("un_distinguishing_sign", "IND"));

    /**
     * The template with every ISO/IEC 18013-5 mandatory element it doesn't declare added to the mDL
     * namespace, so that an mDL can be issued from it. The template's own elements are kept first.
     */
    private static String withMandatoryMdlElements(String template) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode root = (ObjectNode) mapper.readTree(template);
            ObjectNode nameSpaces = root.has("nameSpaces") ? (ObjectNode) root.get("nameSpaces") : root.putObject("nameSpaces");
            ArrayNode items = nameSpaces.has(MDL_NAMESPACE) ? (ArrayNode) nameSpaces.get(MDL_NAMESPACE) : nameSpaces.putArray(MDL_NAMESPACE);
            Set<String> declared = new HashSet<>();
            items.forEach(item -> declared.add(item.path("elementIdentifier").asText()));
            for (String element : MdlDataElements.missingMandatory(declared)) {
                items.addObject()
                        .put("elementIdentifier", element)
                        .set("elementValue", mapper.valueToTree(MANDATORY_SAMPLE_VALUES.get(element)));
            }
            return mapper.writeValueAsString(root);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String cborValue(Map<String, Object> validityInfo, String name) {
        return (String) ((Map<String, Object>) validityInfo.get(name)).get(Constants.__CBOR_VALUE);
    }

    @Test
    public void should_encodeValidityInfoAsTdate_when_msoEncoded() throws Exception {
        String templatedJSON = "{\"docType\": \"org.iso.18013.5.1.mDL\","
                + "\"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\", \"signed\": \"${_signed}\"},"
                + "\"nameSpaces\": {}}";
        Map<String, Object> mDocJson = mDocProcessor.processTemplatedJson(withMandatoryMdlElements(templatedJSON), new HashMap<>(), CERT_NOT_BEFORE);
        mDocJson.put("_holderId", createTestDidJwk());

        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>(), "SHA-256");
        byte[] msoCbor = MDocProcessor.encodeToCBOR(mso);

        co.nstant.in.cbor.model.Map decodedMso = (co.nstant.in.cbor.model.Map)
                new CborDecoder(new ByteArrayInputStream(msoCbor)).decode().getFirst();
        co.nstant.in.cbor.model.Map validityInfo = (co.nstant.in.cbor.model.Map)
                decodedMso.get(new UnicodeString("validityInfo"));

        // The checks the OpenID4VP conformance suite applies to the raw CBOR
        for (String name : List.of("signed", "validFrom", "validUntil")) {
            DataItem timestamp = validityInfo.get(new UnicodeString(name));
            assertNotNull(name + " should be present", timestamp);
            assertTrue(name + " should be a text string", timestamp instanceof UnicodeString);
            assertNotNull(name + " should be tagged", timestamp.getTag());
            assertEquals(name + " should carry tdate tag 0", 0, timestamp.getTag().getValue());
            String text = ((UnicodeString) timestamp).getString();
            assertFalse(name + " should not use fractions of seconds: " + text, text.contains("."));
            assertTrue(name + " should use the UTC offset Z: " + text, text.endsWith("Z"));
        }
    }

    @Test
    public void should_preserveStructure_when_complexElementValueProcessed() throws Exception {
        String templatedJSON = "{"
                + getValidityInfoTemplate()+","
                +"\"docType\": \"org.iso.18013.5.1.mDL\","
                + "\"nameSpaces\": {"
                + "  \"org.iso.18013.5.1\": ["
                + "    {"
                + "      \"digestID\": 7,"
                + "      \"elementIdentifier\": \"driving_privileges\","
                + "      \"elementValue\": ["
                + "        {\"vehicle_category_code\": \"A\", \"issue_date\": \"2020-01-01\"},"
                + "        {\"vehicle_category_code\": \"B\", \"issue_date\": \"2020-01-01\"}"
                + "      ]"
                + "    }"
                + "  ]"
                + "}"
                + "}";

        Map<String, Object> result = mDocProcessor.processTemplatedJson(withMandatoryMdlElements(templatedJSON), new HashMap<>(), CERT_NOT_BEFORE);

        Map<String, Object> nameSpaces = (Map<String, Object>) result.get("nameSpaces");
        List<Map<String, Object>> items = (List<Map<String, Object>>) nameSpaces.get("org.iso.18013.5.1");

        Object elementValue = items.get(0).get("elementValue");
        assertTrue("Element value should be a list", elementValue instanceof List);

        List<Map<String, Object>> privileges = (List<Map<String, Object>>) elementValue;
        assertEquals("Should have 2 privileges", 2, privileges.size());
        assertEquals("A", privileges.get(0).get("vehicle_category_code"));
        assertEquals("B", privileges.get(1).get("vehicle_category_code"));
    }

    @Test
    public void should_returnEmptyMap_when_invalidJsonProcessed() {
        String invalidJSON = "{invalid json}";
        Map<String, Object> result;
        try {
            result = mDocProcessor.processTemplatedJson(invalidJSON, new HashMap<>(), CERT_NOT_BEFORE);
        } catch (Exception e) {
            result = Collections.emptyMap();
        }
        assertNotNull("Result should not be null", result);
        assertTrue("Result should be empty", result.isEmpty());
    }

    @Test
    public void should_throwException_when_validityInfoInvalid() {
        provideValidityInfoTestCases().forEach(args -> {
            String testName = (String) args.get()[0];
            String templatedJSON = (String) args.get()[1];
            String expectedErrorMessage = (String) args.get()[2];

            Map<String, Object> templateParams = new HashMap<>();
            templateParams.put("didUrl", "https://issuer.example.com/did");
            templateParams.put("_holderId", "did:jwk:test123");

            CertifyException exception = assertThrows(CertifyException.class, () ->
                    mDocProcessor.processTemplatedJson(templatedJSON, templateParams, CERT_NOT_BEFORE));

            assertEquals("Test case [" + testName + "] failed", "Error processing templated JSON: "+expectedErrorMessage, exception.getMessage());
        });
    }

    @Test
    public void should_throwException_when_docTypeMissing() {
        String templatedJSON = "{"
                + getValidityInfoTemplate() + ","
                + "\"nameSpaces\": {}"
                + "}";

        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put("didUrl", "https://issuer.example.com/did");
        templateParams.put("_holderId", "did:jwk:test123");

        CertifyException exception = assertThrows(CertifyException.class, () ->
                mDocProcessor.processTemplatedJson(templatedJSON, templateParams, CERT_NOT_BEFORE));

        assertEquals("Error processing templated JSON: Missing docType", exception.getMessage());
    }

    @Test
    public void should_handleAllNamespaces_when_multipleNamespacesProcessed() throws Exception {
        String templatedJSON = "{"
                + "\"docType\": \"org.mosip.credential\","
                + getValidityInfoTemplate()+","
                + "\"nameSpaces\": {"
                + "  \"org.iso.18013.5.1\": ["
                + "    {\"digestID\": 0, \"elementIdentifier\": \"family_name\", \"elementValue\": \"Doe\"}"
                + "  ],"
                + "  \"org.mosip.farmer\": ["
                + "    {\"digestID\": 0, \"elementIdentifier\": \"farmer_id\", \"elementValue\": \"FARM12345\"}"
                + "  ]"
                + "}"
                + "}";

        Map<String, Object> result = mDocProcessor.processTemplatedJson(templatedJSON, new HashMap<>(), CERT_NOT_BEFORE);

        Map<String, Object> nameSpaces = (Map<String, Object>) result.get("nameSpaces");
        assertTrue("Should contain ISO namespace", nameSpaces.containsKey("org.iso.18013.5.1"));
        assertTrue("Should contain custom namespace", nameSpaces.containsKey("org.mosip.farmer"));
    }

    @Test
    public void should_reject_when_anExplicitCborTagIsNot0Or1004() {
        // "1004" is a string, 1004.0 a float, 24 a tag Certify doesn't encode
        for (String tag : List.of("\"1004\"", "1004.0", "24")) {
            String template = customDocumentWith("{\"__cbor_tag\": " + tag + ", \"__cbor_value\": \"2024-06-15\"}");

            CertifyException exception = assertThrows(tag, CertifyException.class,
                    () -> mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE));
            assertEquals(tag, ErrorConstants.MDOC_TEMPLATE_PROCESSING_FAILED, exception.getErrorCode());
            assertTrue(tag, exception.getMessage().endsWith("member_since: __cbor_tag must be the integer 0 (tdate) or 1004 (full-date)"));
        }
    }

    @Test
    public void should_reject_when_aFullDateTagWrapsSomethingElse() {
        for (String content : List.of("\"not-a-date\"", "\"2024-06-15T10:00:00Z\"", "20240615")) {
            String template = customDocumentWith("{\"__cbor_tag\": 1004, \"__cbor_value\": " + content + "}");

            CertifyException exception = assertThrows(content, CertifyException.class,
                    () -> mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE));
            assertTrue(content, exception.getMessage().endsWith("member_since: a value tagged 1004 must be a full-date (YYYY-MM-DD)"));
        }
    }

    @Test
    public void should_reject_when_aTdateTagWrapsSomethingElse() {
        for (String content : List.of("\"yesterday\"", "\"2024-06-15\"", "0")) {
            String template = customDocumentWith("{\"__cbor_tag\": 0, \"__cbor_value\": " + content + "}");

            CertifyException exception = assertThrows(content, CertifyException.class,
                    () -> mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE));
            assertTrue(content, exception.getMessage().endsWith("member_since: a value tagged 0 must be an RFC 3339 date-time"));
        }
    }

    @Test
    public void should_reject_when_aTdateHasNoSeconds() {
        // RFC 3339 requires the seconds; Java's ISO_OFFSET_DATE_TIME alone would accept 10:00Z
        String template = customDocumentWith("{\"__cbor_tag\": 0, \"__cbor_value\": \"2024-06-15T10:00Z\"}");

        CertifyException exception = assertThrows(CertifyException.class,
                () -> mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE));
        assertTrue(exception.getMessage().endsWith("member_since: a value tagged 0 must be an RFC 3339 date-time"));
        assertEquals("Invalid mDL full-date", rejectionMessage("issue_date", "2024-06-15T10:00Z"));
    }

    @Test
    public void should_reject_when_aNestedExplicitTagIsInvalid() {
        String template = customDocumentWith("{\"history\": [{\"since\": {\"__cbor_tag\": 1004, \"__cbor_value\": \"soon\"}}]}");

        CertifyException exception = assertThrows(CertifyException.class,
                () -> mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE));
        assertTrue(exception.getMessage(), exception.getMessage().endsWith("a value tagged 1004 must be a full-date (YYYY-MM-DD)"));
    }

    @Test
    public void should_accept_when_explicitTagsWrapAFullDateAndADateTime() {
        for (String tagged : List.of("{\"__cbor_tag\": 1004, \"__cbor_value\": \"2024-06-15\"}",
                "{\"__cbor_tag\": 0, \"__cbor_value\": \"2024-06-15T10:00:00Z\"}")) {
            assertNotNull(tagged, mDocProcessor.processTemplatedJson(customDocumentWith(tagged), new HashMap<>(), CERT_NOT_BEFORE));
        }
    }

    /** A non-mDL template whose member_since element has the given JSON value. */
    private static String customDocumentWith(String memberSince) {
        return "{\"docType\": \"org.example.custom.document\"," + getValidityInfoTemplate() + ","
                + "\"nameSpaces\": {\"org.example.custom\": ["
                + "  {\"elementIdentifier\": \"member_since\", \"elementValue\": " + memberSince + "}"
                + "]}}";
    }

    // ==================== Random Salt Generation Tests ====================

    @Test
    public void should_addRandomBytes_when_addRandomSaltsCalled() {
        Map<String, Object> mDocJson = createTestMDocJson();

        Map<String, Object> result = MDocProcessor.addRandomSalts(mDocJson);

        assertNotNull("Result should not be null", result);
        List<Map<String, Object>> saltedElements = (List<Map<String, Object>>) result.get("org.iso.18013.5.1");
        assertEquals("Should have 2 elements", 2, saltedElements.size());

        for (Map<String, Object> element : saltedElements) {
            assertTrue("Element should have random salt", element.containsKey("random"));
            byte[] random = (byte[]) element.get("random");
            assertEquals("Salt should be 24 bytes", 24, random.length);
        }
    }

    @Test
    public void should_generateUniqueSalts_when_addRandomSaltsCalled() {
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> nameSpaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();

        for (int i = 0; i < 10; i++) {
            elements.add(createTestElement(i, "field_" + i, "value_" + i));
        }
        nameSpaces.put("org.iso.18013.5.1", elements);
        mDocJson.put("nameSpaces", nameSpaces);

        Map<String, Object> result = MDocProcessor.addRandomSalts(mDocJson);
        List<Map<String, Object>> saltedElements = (List<Map<String, Object>>) result.get("org.iso.18013.5.1");

        Set<String> saltSet = new HashSet<>();
        for (Map<String, Object> element : saltedElements) {
            byte[] random = (byte[]) element.get("random");
            String saltHex = bytesToHex(random);
            assertTrue("Duplicate salt found: " + saltHex, saltSet.add(saltHex));
        }
        assertEquals("All salts should be unique", 10, saltSet.size());
    }

    @Test
    public void should_preserveOriginalData_when_addRandomSaltsCalled() {
        Map<String, Object> mDocJson = createTestMDocJson();

        Map<String, Object> result = MDocProcessor.addRandomSalts(mDocJson);
        List<Map<String, Object>> saltedElements = (List<Map<String, Object>>) result.get("org.iso.18013.5.1");

        assertEquals("family_name", saltedElements.get(0).get("elementIdentifier"));
        assertEquals("Doe", saltedElements.get(0).get("elementValue"));
        assertEquals(0, saltedElements.get(0).get("digestID"));
    }

    // ==================== Digest Calculation Tests ====================

    @Test
    public void should_generateCorrectSHA256Digests_when_calculateDigestsCalled() throws Exception {
        Map<String, Object> saltedNamespaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();
        elements.add(createSaltedElement(0, "family_name", "Doe"));
        saltedNamespaces.put("org.iso.18013.5.1", elements);

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<String, Object> result = MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests, "SHA-256");

        assertNotNull("Result should not be null", result);
        assertTrue("Should contain namespace", result.containsKey("org.iso.18013.5.1"));

        Map<Integer, byte[]> digests = namespaceDigests.get("org.iso.18013.5.1");
        assertNotNull("Digests should not be null", digests);
        assertTrue("Should have digest for ID 0", digests.containsKey(0));
        assertEquals("SHA-256 produces 32 bytes", 32, digests.get(0).length);
    }

    @Test
    public void should_mapDigestsByID_when_multipleElementsProvided() throws Exception {
        Map<String, Object> saltedNamespaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();

        for (int i = 0; i < 5; i++) {
            elements.add(createSaltedElement(i, "field_" + i, "value_" + i));
        }
        saltedNamespaces.put("org.iso.18013.5.1", elements);

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests, "SHA-256");

        Map<Integer, byte[]> digests = namespaceDigests.get("org.iso.18013.5.1");
        assertEquals("Should have 5 digests", 5, digests.size());

        for (int i = 0; i < 5; i++) {
            assertTrue("Should have digest for ID " + i, digests.containsKey(i));
            assertEquals("Digest should be 32 bytes", 32, digests.get(i).length);
        }
    }

    @Test
    public void should_wrapWithCBORTag24_when_calculateDigestsCalled() throws Exception {
        Map<String, Object> saltedNamespaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();
        elements.add(createSaltedElement(0, "test", "value"));
        saltedNamespaces.put("org.iso.18013.5.1", elements);

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<String, Object> result = MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests, "SHA-256");

        List<Object> taggedElements = (List<Object>) result.get("org.iso.18013.5.1");
        assertNotNull("Tagged elements should not be null", taggedElements);
        assertEquals("Should have 1 element", 1, taggedElements.size());

        Object element = taggedElements.get(0);
        assertTrue("Element should be ByteString", element instanceof ByteString);

        ByteString byteString = (ByteString) element;
        assertEquals("Should have tag 24", 24, byteString.getTag().getValue());
    }

    @Test
    public void should_verifyDigestCalculation_when_calculateDigestsCalled() throws Exception {
        // Create element with known data
        Map<String, Object> element = new HashMap<>();
        element.put("digestID", 0);
        element.put("elementIdentifier", "test_field");
        element.put("elementValue", "test_value");
        element.put("random", new byte[24]); // All zeros for reproducibility

        Map<String, Object> saltedNamespaces = new HashMap<>();
        saltedNamespaces.put("test.namespace", Collections.singletonList(element));

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests, "SHA-256");

        byte[] digest = namespaceDigests.get("test.namespace").get(0);

        // Verify digest is deterministic for same input
        Map<String, Map<Integer, byte[]>> namespaceDigests2 = new HashMap<>();
        MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests2, "SHA-256");
        byte[] digest2 = namespaceDigests2.get("test.namespace").get(0);

        assertArrayEquals("Digests should be deterministic", digest, digest2);
    }

    // ==================== CBOR Encoding Tests ====================

    @Test
    public void should_encodeSuccessfully_when_simpleMapEncoded() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("key", "value");
        data.put("number", 42);
        data.put("boolean", true);

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);

        // Verify it can be decoded
        List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(result)).decode();
        assertFalse("Should decode successfully", decoded.isEmpty());
    }

    @Test
    public void should_preserveBytes_when_byteArrayEncoded() throws Exception {
        byte[] testBytes = new byte[]{1, 2, 3, 4, 5};
        Map<String, Object> data = new HashMap<>();
        data.put("bytes", testBytes);

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);

        // Decode and verify
        List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(result)).decode();
        co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map) decoded.get(0);
        ByteString byteString = (ByteString) map.get(new UnicodeString("bytes"));
        assertArrayEquals("Bytes should be preserved", testBytes, byteString.getBytes());
    }

    @Test
    public void should_encodeRecursively_when_nestedStructuresEncoded() throws Exception {
        Map<String, Object> nested = new HashMap<>();
        nested.put("inner", "value");
        nested.put("innerNumber", 123);

        Map<String, Object> data = new HashMap<>();
        data.put("outer", nested);
        data.put("list", Arrays.asList(1, 2, 3));

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);
    }

    @Test
    public void should_leaveDateStringUntagged_when_encodedOutsideAnMdlElement() throws Exception {
        // Only Table 5 full-date elements are tagged 1004 (ISO/IEC 18013-5); a date-looking
        // string anywhere else stays text.
        Map<String, Object> data = new HashMap<>();
        data.put("birthDate", "1990-08-25");

        byte[] result = MDocProcessor.encodeToCBOR(data);

        co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map)
                new CborDecoder(new ByteArrayInputStream(result)).decode().get(0);
        DataItem date = map.get(new UnicodeString("birthDate"));
        assertEquals(new UnicodeString("1990-08-25"), date);
        assertFalse(date.hasTag());
    }

    @Test
    public void should_handleCorrectly_when_allDataTypesEncoded() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("string", "test");
        data.put("integer", 42);
        data.put("long", 1234567890L);
        data.put("double", 3.14);
        data.put("boolean", true);
        data.put("null", null);
        data.put("bytes", new byte[]{1, 2, 3});
        data.put("list", Arrays.asList(1, 2, 3));
        data.put("map", Collections.singletonMap("nested", "value"));

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);
    }

    @Test
    public void should_handleGracefully_when_nullInputEncoded() throws Exception {
        // Null is handled by preprocessForCBOR and converted to SimpleValue.NULL
        byte[] result = MDocProcessor.encodeToCBOR(Collections.singletonMap("nullKey", null));

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);
    }

    // ==================== Date Handling Tests ====================

    @Test
    public void should_tagFullDate_when_mdlBirthDateIsAValidDate() throws Exception {
        String[] validDates = {
                "2025-01-15",
                "1990-12-31",
                "2000-02-29", // Leap year
                "2024-06-30"
        };

        for (String date : validDates) {
            DataItem dateItem = encodedElementValue(MDL_NAMESPACE, "birth_date", date);
            // UnicodeString.equals compares the tag too, so the text is compared on its own
            assertEquals(date, ((UnicodeString) dateItem).getString());
            assertEquals("Should have tag 1004 for date: " + date, 1004, dateItem.getTag().getValue());
        }
    }

    @Test
    public void should_tagEveryFullDateElement_when_mdlValuesAreDateOnly() throws Exception {
        for (String identifier : List.of("birth_date", "issue_date", "expiry_date")) {
            assertEquals(identifier, 1004, encodedElementValue(MDL_NAMESPACE, identifier, "2024-06-15").getTag().getValue());
        }
    }

    @Test
    public void should_notTagDate_when_mdlTextElementLooksLikeADate() throws Exception {
        // document_number is text in Table 5, whatever its value looks like.
        DataItem value = encodedElementValue(MDL_NAMESPACE, "document_number", "2024-06-15");
        assertEquals(new UnicodeString("2024-06-15"), value);
        assertFalse(value.hasTag());
    }

    @Test
    public void should_notTagDate_when_namespaceIsNotTheMdlNamespace() throws Exception {
        DataItem value = encodedElementValue("org.example.custom", "birth_date", "1990-08-25");
        assertEquals(new UnicodeString("1990-08-25"), value);
        assertFalse(value.hasTag());
    }

    @Test
    public void should_keepExplicitTag_when_templateTagsAValueOutsideTheMdlNamespace() throws Exception {
        // A non-mDL template that needs a full-date says so itself.
        Map<String, Object> tagged = new HashMap<>();
        tagged.put(Constants.__CBOR_TAG, 1004);
        tagged.put(Constants.__CBOR_VALUE, "1990-08-25");

        DataItem value = encodedElementValue("org.example.custom", "birth_date", tagged);

        assertEquals("1990-08-25", ((UnicodeString) value).getString());
        assertEquals(1004, value.getTag().getValue());
    }

    @Test
    public void should_tagNestedDates_when_drivingPrivilegesCarryIssueAndExpiryDates() throws Exception {
        Map<String, Object> category = new HashMap<>();
        category.put("vehicle_category_code", "B");
        category.put("issue_date", "2024-06-15");
        category.put("expiry_date", "2044-06-14");

        Array privileges = (Array) encodedElementValue(MDL_NAMESPACE, "driving_privileges",
                List.of(category, Map.of("vehicle_category_code", "A")));

        co.nstant.in.cbor.model.Map first = (co.nstant.in.cbor.model.Map) privileges.getDataItems().get(0);
        assertEquals(1004, first.get(new UnicodeString("issue_date")).getTag().getValue());
        assertEquals(1004, first.get(new UnicodeString("expiry_date")).getTag().getValue());
        assertFalse(first.get(new UnicodeString("vehicle_category_code")).hasTag());
        assertEquals(2, privileges.getDataItems().size());
    }

    @Test
    public void should_reject_when_drivingPrivilegesIsNotAnArray() {
        for (Object value : List.of("B", Map.of("vehicle_category_code", "B"))) {
            assertEquals("driving_privileges must be an array", rejectionMessage("driving_privileges", value));
        }
    }

    @Test
    public void should_reject_when_drivingPrivilegesEntryHasNoVehicleCategoryCode() {
        // 7.2.4: each entry is a map with a text vehicle_category_code
        Map<String, Object> blankCode = new HashMap<>();
        blankCode.put("vehicle_category_code", " ");
        for (Object entry : List.of("B", Map.of("issue_date", "2024-06-15"), blankCode,
                Map.of("vehicle_category_code", 5))) {
            assertEquals("Invalid driving_privileges entry", rejectionMessage("driving_privileges", List.of(entry)));
        }
    }

    @Test
    public void should_reject_when_drivingPrivilegesEntryHasAKeyOutsideDrivingPrivilege() {
        Map<String, Object> entry = Map.of("vehicle_category_code", "B", "category", "car");

        assertEquals("Invalid driving_privileges entry", rejectionMessage("driving_privileges", List.of(entry)));
    }

    @Test
    public void should_reject_when_drivingPrivilegeCodesAreNotCodeEntries() {
        // 7.2.4: codes is [+ Code], Code = {code: tstr, ? sign: tstr, ? value: tstr}
        List<Object> invalidCodes = List.of("78", List.of(), List.of("78"), List.of(Map.of("sign", "<=")),
                List.of(Map.of("code", " ")), List.of(Map.of("code", 78)),
                List.of(Map.of("code", "78", "sign", 1)), List.of(Map.of("code", "78", "value", 3500)),
                List.of(Map.of("code", "78", "note", "automatic")));
        for (Object codes : invalidCodes) {
            Map<String, Object> entry = Map.of("vehicle_category_code", "B", "codes", codes);
            assertEquals("codes " + codes, "Invalid driving_privileges entry", rejectionMessage("driving_privileges", List.of(entry)));
        }
    }

    @Test
    public void should_encodeCodes_when_drivingPrivilegeCodesAreCodeEntries() throws Exception {
        Map<String, Object> entry = Map.of("vehicle_category_code", "C", "issue_date", "2024-06-15",
                "codes", List.of(Map.of("code", "78"), Map.of("code", "01", "sign", "<=", "value", "3500")));

        Array privileges = (Array) encodedElementValue(MDL_NAMESPACE, "driving_privileges", List.of(entry));

        co.nstant.in.cbor.model.Map encoded = (co.nstant.in.cbor.model.Map) privileges.getDataItems().get(0);
        Array codes = (Array) encoded.get(new UnicodeString("codes"));
        assertEquals(2, codes.getDataItems().size());
        co.nstant.in.cbor.model.Map second = (co.nstant.in.cbor.model.Map) codes.getDataItems().get(1);
        assertEquals(new UnicodeString("3500"), second.get(new UnicodeString("value")));
        assertEquals(1004, encoded.get(new UnicodeString("issue_date")).getTag().getValue());
    }

    @Test
    public void should_acceptAnEmptyArray_when_drivingPrivilegesHasNoEntries() throws Exception {
        assertEquals(0, ((Array) encodedElementValue(MDL_NAMESPACE, "driving_privileges", List.of())).getDataItems().size());
    }

    @Test
    public void should_reject_when_fullDateHasTheWrongTypeOrTag() {
        // A value the template tagged itself meets the explicit-tag check first (any namespace), so a
        // tag that is not 0 or 1004, or does not wrap a date or date-time, is rejected there.
        Map<Object, String> invalidBirthDates = new LinkedHashMap<>();
        invalidBirthDates.put(19900825, "Invalid mDL full-date");
        invalidBirthDates.put(List.of("1990-08-25"), "Invalid mDL full-date");
        invalidBirthDates.put(Map.of(Constants.__CBOR_TAG, 0, Constants.__CBOR_VALUE, "1990-08-25T00:00:00Z"),
                "Invalid mDL full-date");
        invalidBirthDates.put(Map.of(Constants.__CBOR_TAG, 1004, Constants.__CBOR_VALUE, "not-a-date"),
                "birth_date: a value tagged 1004 must be a full-date (YYYY-MM-DD)");
        invalidBirthDates.forEach((value, message) ->
                assertEquals(String.valueOf(value), message, rejectionMessage("birth_date", value)));
        // a tdate holds a date-time, and no other tag is allowed
        Map<Object, String> invalidIssueDates = new LinkedHashMap<>();
        invalidIssueDates.put(Map.of(Constants.__CBOR_TAG, 5, Constants.__CBOR_VALUE, "2024-06-15"),
                "issue_date: __cbor_tag must be the integer 0 (tdate) or 1004 (full-date)");
        invalidIssueDates.put(Map.of(Constants.__CBOR_TAG, 0, Constants.__CBOR_VALUE, "not-a-date-time"),
                "issue_date: a value tagged 0 must be an RFC 3339 date-time");
        invalidIssueDates.put(Map.of(Constants.__CBOR_TAG, 0, Constants.__CBOR_VALUE, "2024-06-15"),
                "issue_date: a value tagged 0 must be an RFC 3339 date-time");
        invalidIssueDates.forEach((value, message) ->
                assertEquals(String.valueOf(value), message, rejectionMessage("issue_date", value)));
    }

    @Test
    public void should_keepTheTag_when_templateTagsAValidMdlDate() throws Exception {
        DataItem birthDate = encodedElementValue(MDL_NAMESPACE, "birth_date",
                Map.of(Constants.__CBOR_TAG, 1004, Constants.__CBOR_VALUE, "1990-08-25"));
        assertEquals("1990-08-25", ((UnicodeString) birthDate).getString());
        assertEquals(1004, birthDate.getTag().getValue());

        DataItem issueDate = encodedElementValue(MDL_NAMESPACE, "issue_date",
                Map.of(Constants.__CBOR_TAG, 0, Constants.__CBOR_VALUE, "2024-06-15T10:00:00+02:00"));
        assertEquals("2024-06-15T08:00:00Z", ((UnicodeString) issueDate).getString());
        assertEquals(0, issueDate.getTag().getValue());
    }

    @Test
    public void should_reject_when_mdlFullDateIsNotADate() {
        // birth_date is a full-date only, so a date-time is rejected as well
        for (String text : List.of("not-a-date", "1990-08-25T00:00:00Z")) {
            // the value is left out of the message, so a date of birth is not logged
            assertEquals("Invalid mDL full-date", rejectionMessage("birth_date", text));
        }
    }

    @Test
    public void should_reject_when_drivingPrivilegeDateIsNotAFullDate() {
        Map<String, Object> category = Map.of("vehicle_category_code", "B", "issue_date", "2024-06-15T10:00:00Z");

        assertEquals("Invalid mDL full-date", rejectionMessage("driving_privileges", List.of(category)));
    }

    @Test
    public void should_encodeAsTdate_when_issueOrExpiryDateIsADateTime() throws Exception {
        // a tdate is in UTC without fractions of seconds
        DataItem issueDate = encodedElementValue(MDL_NAMESPACE, "issue_date", "2024-06-15T10:00:00+02:00");
        assertEquals("2024-06-15T08:00:00Z", ((UnicodeString) issueDate).getString());
        assertEquals(0, issueDate.getTag().getValue());

        DataItem expiryDate = encodedElementValue(MDL_NAMESPACE, "expiry_date", "2044-06-14T23:59:59.500Z");
        assertEquals("2044-06-14T23:59:59Z", ((UnicodeString) expiryDate).getString());
        assertEquals(0, expiryDate.getTag().getValue());
    }

    @Test
    public void should_reject_when_issueDateIsNeitherADateNorADateTime() {
        assertEquals("Invalid mDL full-date", rejectionMessage("issue_date", "15/06/2024"));
    }

    @Test
    public void should_encodePortraitAsBytes_when_templateCarriesBase64() throws Exception {
        byte[] jpeg = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, (byte) 0xFB};

        // base64url without padding and plain base64 with padding are both accepted
        for (String text : List.of(Base64.getUrlEncoder().withoutPadding().encodeToString(jpeg),
                Base64.getEncoder().encodeToString(jpeg))) {
            DataItem portrait = encodedElementValue(MDL_NAMESPACE, "portrait", text);
            assertEquals(new ByteString(jpeg), portrait);
        }
    }

    @Test
    public void should_encodePortraitAsBytes_when_templateCarriesADataUri() throws Exception {
        byte[] jpeg = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, (byte) 0xFB};

        DataItem portrait = encodedElementValue(MDL_NAMESPACE, "portrait",
                "data:image/jpeg;base64," + Base64.getEncoder().encodeToString(jpeg));

        assertEquals(new ByteString(jpeg), portrait);
    }

    @Test
    public void should_reject_when_portraitIsNotBase64() {
        assertEquals("portrait must be base64 encoded", rejectionMessage("portrait", "not base64!"));
    }

    @Test
    public void should_reject_when_portraitIsNotText() {
        for (Object value : List.of(List.of(255, 216, 255), 42, Map.of("data", "AQID"))) {
            assertEquals("portrait must be base64 encoded", rejectionMessage("portrait", value));
        }
    }

    @Test
    public void should_acceptPortrait_when_itIsAJpeg2000CodestreamOrJp2File() throws Exception {
        byte[] codestream = {(byte) 0xFF, 0x4F, (byte) 0xFF, 0x51, 0x00};
        byte[] jp2 = {0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A};

        for (byte[] image : List.of(codestream, jp2)) {
            String template = withMandatoryMdlElements(mdlTemplateWithPortrait(Base64.getEncoder().encodeToString(image)));
            assertNotNull(mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE));
        }
    }

    @Test
    public void should_reject_when_portraitIsAPng() {
        byte[] png = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
        String base64 = Base64.getEncoder().encodeToString(png);

        for (String value : List.of(base64, "data:image/png;base64," + base64)) {
            assertEquals("portrait must be a JPEG or JPEG2000 image", rejectionMessage("portrait", value));
        }
    }

    @Test
    public void should_reject_when_portraitIsEmpty() {
        assertEquals("portrait must be a JPEG or JPEG2000 image", rejectionMessage("portrait", ""));
    }

    @Test
    public void should_reject_when_portraitIsShorterThanAnImageSignature() {
        String truncatedJpeg = Base64.getEncoder().encodeToString(new byte[]{(byte) 0xFF, (byte) 0xD8});
        assertEquals("portrait must be a JPEG or JPEG2000 image", rejectionMessage("portrait", truncatedJpeg));
    }

    @Test
    public void should_encodeAsBytes_when_elementIsASignatureMarkOrBiometricTemplate() throws Exception {
        byte[] data = {0x01, 0x02, (byte) 0xFE, (byte) 0xFF};
        String base64 = Base64.getEncoder().encodeToString(data);

        for (String identifier : List.of("signature_usual_mark", "biometric_template_face",
                "biometric_template_finger")) {
            assertEquals(identifier, new ByteString(data), encodedElementValue(MDL_NAMESPACE, identifier, base64));
        }
    }

    @Test
    public void should_keepPortraitAsText_when_namespaceIsNotTheMdlNamespace() throws Exception {
        DataItem value = encodedElementValue("org.example.custom", "portrait", "AQID");
        assertEquals(new UnicodeString("AQID"), value);
    }

    @Test
    public void should_encodePortraitAsBytes_when_photoIdTemplateCarriesBase64OrADataUri() throws Exception {
        byte[] jpeg = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, (byte) 0xFB};
        String base64 = Base64.getEncoder().encodeToString(jpeg);

        for (String text : List.of(base64, "data:image/jpeg;base64," + base64)) {
            assertEquals(new ByteString(jpeg), encodedElementValue(PhotoIdDataElements.NAMESPACE, "portrait", text));
        }
    }

    @Test
    public void should_keepOtherElementsAsText_when_photoIdElementIsNotAByteString() throws Exception {
        assertEquals(new UnicodeString("AQID"), encodedElementValue(PhotoIdDataElements.NAMESPACE, "family_name", "AQID"));
    }

    @Test
    public void should_acceptPhotoIdPortrait_when_itIsAJpegOrJpeg2000Image() throws Exception {
        byte[] jpeg = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0};
        byte[] codestream = {(byte) 0xFF, 0x4F, (byte) 0xFF, 0x51, 0x00};

        for (byte[] image : List.of(jpeg, codestream)) {
            String template = "{\"docType\": \"" + PhotoIdDataElements.DOC_TYPE + "\","
                    + "\"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\", \"signed\": \"${_signed}\"},"
                    + "\"nameSpaces\": {\"" + PhotoIdDataElements.NAMESPACE + "\": ["
                    + "{\"elementIdentifier\": \"portrait\", \"elementValue\": \"" + Base64.getEncoder().encodeToString(image) + "\"}]}}";
            assertNotNull(mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE));
        }
    }

    @Test
    public void should_reject_when_photoIdPortraitIsNotABase64JpegOrJpeg2000Image() {
        String png = Base64.getEncoder().encodeToString(new byte[]{(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A});

        assertEquals("portrait must be a JPEG or JPEG2000 image", photoIdRejectionMessage("portrait", png));
        assertEquals("portrait must be a JPEG or JPEG2000 image", photoIdRejectionMessage("portrait", ""));
        assertEquals("portrait must be base64 encoded", photoIdRejectionMessage("portrait", "not base64!"));
        assertEquals("portrait must be base64 encoded", photoIdRejectionMessage("portrait", 42));
    }

    @Test
    public void should_encodeIssueAndExpiryDatesAsFullDates_when_photoIdTemplateCarriesDates() throws Exception {
        for (String identifier : List.of("issue_date", "expiry_date")) {
            DataItem date = encodedElementValue(PhotoIdDataElements.NAMESPACE, identifier, "2026-01-15");
            assertEquals(identifier, 1004, date.getTag().getValue());
            assertEquals(identifier, "2026-01-15", ((UnicodeString) date).getString());
        }
    }

    @Test
    public void should_encodePortraitCaptureDateAsTdateInUtc_when_photoIdTemplateCarriesADateTime() throws Exception {
        // converted to UTC, without fractions of seconds, as the mDL dates are
        for (String text : List.of("2026-01-10T09:30:00Z", "2026-01-10T15:00:00.250+05:30")) {
            DataItem captured = encodedElementValue(PhotoIdDataElements.NAMESPACE, "portrait_capture_date", text);
            assertEquals(text, 0, captured.getTag().getValue());
            assertEquals(text, "2026-01-10T09:30:00Z", ((UnicodeString) captured).getString());
        }
    }

    @Test
    public void should_encodeBirthDateAsFullDate_when_photoIdBirthDateIsADate() throws Exception {
        DataItem birthDate = encodedElementValue(PhotoIdDataElements.NAMESPACE, "birth_date", "1985-04-29");

        assertEquals(1004, birthDate.getTag().getValue());
        assertEquals("1985-04-29", ((UnicodeString) birthDate).getString());
    }

    @Test
    public void should_tagTheDateInsideTheMap_when_photoIdBirthDateIsABirthDateMap() throws Exception {
        // ISO/IEC TS 23220-2, 6.3.1.1.3: the date inside the map is a full-date, the mask stays text
        co.nstant.in.cbor.model.Map birthDate = (co.nstant.in.cbor.model.Map) encodedElementValue(PhotoIdDataElements.NAMESPACE,
                "birth_date", Map.of("birth_date", "1985-01-01", "approximate_mask", "00001111"));

        DataItem date = birthDate.get(new UnicodeString("birth_date"));
        assertEquals(1004, date.getTag().getValue());
        assertEquals("1985-01-01", ((UnicodeString) date).getString());
        DataItem mask = birthDate.get(new UnicodeString("approximate_mask"));
        assertFalse(mask.hasTag());
        assertEquals("00001111", ((UnicodeString) mask).getString());
        assertEquals(2, birthDate.getKeys().size());
    }

    @Test
    public void should_acceptBirthDateMap_when_itHasNoApproximateMask() throws Exception {
        String template = "{\"docType\": \"" + PhotoIdDataElements.DOC_TYPE + "\","
                + "\"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\", \"signed\": \"${_signed}\"},"
                + "\"nameSpaces\": {\"" + PhotoIdDataElements.NAMESPACE + "\": ["
                + "{\"elementIdentifier\": \"birth_date\", \"elementValue\": {\"birth_date\": \"1985-04-29\"}}]}}";

        assertNotNull(mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE));
    }

    @Test
    public void should_reject_when_photoIdBirthDateIsNeitherAFullDateNorABirthDateMap() {
        String expected = "birth_date must be a full-date (YYYY-MM-DD) or a map with a full-date birth_date and an optional approximate_mask";
        for (Object value : List.of("1985-04-29T00:00:00Z", "29/04/1985", 19850429,
                Map.of("approximate_mask", "00000000"),
                Map.of("birth_date", "29/04/1985"),
                Map.of("birth_date", "1985-04-29", "place", "Bengaluru"))) {
            assertEquals(String.valueOf(value), expected, photoIdRejectionMessage("birth_date", value));
        }
    }

    @Test
    public void should_reject_when_photoIdBirthDateMaskIsNotEightBinaryDigits() {
        for (Object mask : List.of("0000", "00000002", "000011110", 11110000)) {
            assertEquals(String.valueOf(mask), "birth_date: approximate_mask must be 8 digits, each 0 or 1",
                    photoIdRejectionMessage("birth_date", Map.of("birth_date", "1985-01-01", "approximate_mask", mask)));
        }
    }

    @Test
    public void should_acceptAndEncodeAsCborBoolean_when_photoIdAgeOverIsABoolean() throws Exception {
        String template = "{\"docType\": \"" + PhotoIdDataElements.DOC_TYPE + "\","
                + "\"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\", \"signed\": \"${_signed}\"},"
                + "\"nameSpaces\": {\"" + PhotoIdDataElements.NAMESPACE + "\": ["
                + "{\"elementIdentifier\": \"age_over_18\", \"elementValue\": true},"
                + "{\"elementIdentifier\": \"age_over_65\", \"elementValue\": false}]}}";

        assertNotNull(mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE));
        assertEquals(SimpleValue.TRUE, encodedElementValue(PhotoIdDataElements.NAMESPACE, "age_over_18", true));
        assertEquals(SimpleValue.FALSE, encodedElementValue(PhotoIdDataElements.NAMESPACE, "age_over_65", false));
    }

    @Test
    public void should_reject_when_photoIdAgeOverIsNotABoolean() {
        // a quoted "true" is the usual mistake: "elementValue": "${ageOver18}" instead of ${ageOver18}
        for (String identifier : List.of("age_over_18", "age_over_21")) {
            for (Object value : List.of("true", "false", "yes", 1, 0, Map.of("value", true))) {
                assertEquals(identifier + "=" + value, identifier + " must be a boolean (true or false), not text or a number",
                        photoIdRejectionMessage(identifier, value));
            }
        }
    }

    @Test
    public void should_accept_when_photoIdAgeInYearsAndBirthYearAreUnsignedIntegers() throws Exception {
        for (Object value : List.of(0, 41, 1985L, new BigInteger("18446744073709551615"))) {
            String template = "{\"docType\": \"" + PhotoIdDataElements.DOC_TYPE + "\","
                    + "\"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\", \"signed\": \"${_signed}\"},"
                    + "\"nameSpaces\": {\"" + PhotoIdDataElements.NAMESPACE + "\": ["
                    + "{\"elementIdentifier\": \"age_in_years\", \"elementValue\": " + value + "},"
                    + "{\"elementIdentifier\": \"age_birth_year\", \"elementValue\": " + value + "}]}}";
            assertNotNull(String.valueOf(value), mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE));
        }
    }

    @Test
    public void should_reject_when_photoIdAgeInYearsOrBirthYearIsNotAnUnsignedInteger() {
        // a quoted "${ageInYears}" renders as text; a negative number is not a uint (ISO/IEC TS 23220-4, Annex C)
        for (String identifier : List.of("age_in_years", "age_birth_year")) {
            for (Object value : List.of("41", -1, 41.5, true)) {
                assertEquals(identifier + "=" + value, identifier + " must be an unsigned integer",
                        photoIdRejectionMessage(identifier, value));
            }
        }
    }

    @Test
    public void should_keepNegativeIntegers_when_elementIsOutsideThePhotoIdUnsignedElements() throws Exception {
        // only age_in_years and age_birth_year in org.iso.23220.1 must be unsigned; other elements and namespaces keep signed integers
        assertEquals(new NegativeInteger(-1), encodedElementValue("org.example.custom", "age_in_years", -1));
        String template = "{\"docType\": \"" + PhotoIdDataElements.DOC_TYPE + "\","
                + "\"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\", \"signed\": \"${_signed}\"},"
                + "\"nameSpaces\": {\"org.example.custom\": [{\"elementIdentifier\": \"age_in_years\", \"elementValue\": -1}]}}";
        assertNotNull(mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE));
    }

    @Test
    public void should_notCheckAsAgeOver_when_identifierOnlyLooksLikeOne() throws Exception {
        // age_over_NN has exactly two digits; anything else is an ordinary element
        for (String identifier : List.of("age_over_100", "age_over_x", "age_over_1")) {
            assertEquals(identifier, new UnicodeString("yes"), encodedElementValue(PhotoIdDataElements.NAMESPACE, identifier, "yes"));
            String template = "{\"docType\": \"" + PhotoIdDataElements.DOC_TYPE + "\","
                    + "\"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\", \"signed\": \"${_signed}\"},"
                    + "\"nameSpaces\": {\"" + PhotoIdDataElements.NAMESPACE + "\": ["
                    + "{\"elementIdentifier\": \"" + identifier + "\", \"elementValue\": \"yes\"}]}}";
            assertNotNull(identifier, mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE));
        }
    }

    @Test
    public void should_keepADateAsText_when_photoIdElementIsNotADateElement() throws Exception {
        DataItem value = encodedElementValue(PhotoIdDataElements.NAMESPACE, "document_number", "2026-01-15");
        assertFalse(value.hasTag());
    }

    @Test
    public void should_reject_when_photoIdIssueOrExpiryDateIsNotAFullDate() {
        // ISO/IEC TS 23220-4 Annex C: full-date only, unlike the mDL, which also allows a date-time
        for (String identifier : List.of("issue_date", "expiry_date")) {
            for (Object value : List.of("2026-01-15T00:00:00Z", "15/01/2026", 20260115,
                    Map.of("__cbor_tag", 0, "__cbor_value", "2026-01-15T00:00:00Z"))) {
                assertEquals(identifier + " must be a full-date (YYYY-MM-DD)", photoIdRejectionMessage(identifier, value));
            }
        }
    }

    @Test
    public void should_reject_when_photoIdPortraitCaptureDateIsNotADateTime() {
        for (Object value : List.of("2026-01-10", "10/01/2026 09:30", 1768037400)) {
            assertEquals("portrait_capture_date must be an RFC 3339 date-time",
                    photoIdRejectionMessage("portrait_capture_date", value));
        }
    }

    @Test
    public void should_leaveOutElement_when_itsValueIsNull() throws Exception {
        String template = "{\"docType\": \"" + PhotoIdDataElements.DOC_TYPE + "\","
                + "\"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\", \"signed\": \"${_signed}\"},"
                + "\"nameSpaces\": {"
                + "\"" + PhotoIdDataElements.NAMESPACE + "\": ["
                + "{\"elementIdentifier\": \"family_name\", \"elementValue\": \"Doe\"},"
                + "{\"elementIdentifier\": \"nationality\", \"elementValue\": null},"
                + "{\"elementIdentifier\": \"portrait_capture_date\", \"elementValue\": null}],"
                + "\"org.iso.23220.photoid.1\": ["
                + "{\"elementIdentifier\": \"person_id\", \"elementValue\": null}]}}";

        Map<String, Object> nameSpaces = (Map<String, Object>)
                mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE).get("nameSpaces");

        List<Map<String, Object>> elements = (List<Map<String, Object>>) nameSpaces.get(PhotoIdDataElements.NAMESPACE);
        assertEquals(List.of("family_name"), elements.stream().map(element -> element.get("elementIdentifier")).toList());
        // a namespace left without elements is left out
        assertFalse(nameSpaces.containsKey("org.iso.23220.photoid.1"));
    }

    @Test
    public void should_encodeAsCborInteger_when_integerIsBeyondALongOrAShortOrByte() throws Exception {
        BigInteger largest = new BigInteger("18446744073709551615"); // 2^64 - 1
        BigInteger smallest = new BigInteger("-18446744073709551616"); // -2^64

        DataItem large = encodedElementValue(PhotoIdDataElements.NAMESPACE, "age_in_years", largest);
        DataItem small = encodedElementValue(PhotoIdDataElements.NAMESPACE, "age_in_years", smallest);

        // plain CBOR integers, not text and not tagged bignums
        assertEquals(largest, ((UnsignedInteger) large).getValue());
        assertFalse(large.hasTag());
        assertEquals(smallest, ((NegativeInteger) small).getValue());
        assertFalse(small.hasTag());
        assertEquals(new UnsignedInteger(41), encodedElementValue(PhotoIdDataElements.NAMESPACE, "age_in_years", (short) 41));
        assertEquals(new UnsignedInteger(9), encodedElementValue(PhotoIdDataElements.NAMESPACE, "sex", (byte) 9));
    }

    @Test
    public void should_reject_when_integerIsBeyondTheCborIntegerRange() {
        for (BigInteger value : List.of(new BigInteger("18446744073709551616"), new BigInteger("-18446744073709551617"))) {
            assertEquals("age_in_years: an integer must be between -2^64 and 2^64 - 1",
                    photoIdRejectionMessage("age_in_years", value));
            // at any depth
            assertEquals("birth_date: an integer must be between -2^64 and 2^64 - 1",
                    photoIdRejectionMessage("birth_date", Map.of("approximate_mask", List.of(value))));
        }
    }

    @Test
    public void should_reject_when_numberHasNoExactCborEncoding() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> encodedElementValue(PhotoIdDataElements.NAMESPACE, "age_in_years", new BigDecimal("41.5")));
        assertEquals("Unsupported number type: BigDecimal", exception.getMessage());
    }

    @Test
    public void should_rejectNamingTheElement_when_templateElementLacksItsIdentifierOrValue() {
        String valid = "{\"elementIdentifier\": \"given_name\", \"elementValue\": \"John\"}";
        String path = "nameSpaces." + PhotoIdDataElements.NAMESPACE + "[1]";
        Map<String, String> expected = new LinkedHashMap<>();
        expected.put("{\"elementValue\": \"Doe\"}", path + ": elementIdentifier is missing");
        expected.put("{\"elementIdentifier\": \" \", \"elementValue\": \"Doe\"}", path + ": elementIdentifier is missing");
        expected.put("{\"elementIdentifier\": 5, \"elementValue\": \"Doe\"}", path + ": elementIdentifier is missing");
        expected.put("{\"elementIdentifier\": \"family_name\"}", path + " (family_name): elementValue is missing");
        expected.put("\"family_name\"", path + " must be an object with elementIdentifier and elementValue");

        expected.forEach((element, message) -> assertEquals(element, message, templateRejectionMessage(
                "{\"" + PhotoIdDataElements.NAMESPACE + "\": [" + valid + ", " + element + "]}")));
    }

    @Test
    public void should_rejectNamingTheNamespace_when_nameSpacesOrANamespaceHasTheWrongShape() {
        assertEquals("nameSpaces." + PhotoIdDataElements.NAMESPACE + " must be an array of elements",
                templateRejectionMessage("{\"" + PhotoIdDataElements.NAMESPACE + "\": {\"family_name\": \"Doe\"}}"));
        assertEquals("nameSpaces must be an object mapping each namespace to its elements",
                templateRejectionMessage("[{\"elementIdentifier\": \"family_name\", \"elementValue\": \"Doe\"}]"));
    }

    @Test
    public void should_reject_when_namespaceDeclaresAnElementIdentifierTwice() {
        // e.g. a template that renders its elements through ${elements}, which Add and Update can't check
        for (String namespace : List.of(PhotoIdDataElements.NAMESPACE, MDL_NAMESPACE)) {
            assertEquals(namespace, "nameSpaces." + namespace + "[2]: elementIdentifier family_name is declared more than once in nameSpaces." + namespace,
                    templateRejectionMessage("{\"" + namespace + "\": ["
                            + "{\"elementIdentifier\": \"family_name\", \"elementValue\": \"Doe\"},"
                            + "{\"elementIdentifier\": \"given_name\", \"elementValue\": \"John\"},"
                            + "{\"elementIdentifier\": \"family_name\", \"elementValue\": \"Roe\"}]}"));
        }
    }

    @Test
    public void should_accept_when_anIdentifierRepeatsInAnotherNamespaceOrOnlyWithANullValue() throws Exception {
        // the same identifier may appear once in each namespace, and a null element is left out before the check
        String template = "{\"docType\": \"" + PhotoIdDataElements.DOC_TYPE + "\","
                + "\"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\", \"signed\": \"${_signed}\"},"
                + "\"nameSpaces\": {"
                + "\"" + PhotoIdDataElements.NAMESPACE + "\": ["
                + "{\"elementIdentifier\": \"family_name\", \"elementValue\": null},"
                + "{\"elementIdentifier\": \"family_name\", \"elementValue\": \"Doe\"}],"
                + "\"org.iso.23220.photoid.1\": [{\"elementIdentifier\": \"family_name\", \"elementValue\": \"Doe\"}]}}";

        Map<String, Object> nameSpaces = (Map<String, Object>)
                mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE).get("nameSpaces");

        assertEquals(1, ((List<?>) nameSpaces.get(PhotoIdDataElements.NAMESPACE)).size());
        assertEquals(1, ((List<?>) nameSpaces.get("org.iso.23220.photoid.1")).size());
    }

    /** The reason processTemplatedJson rejects a Photo ID template with these nameSpaces. */
    private String templateRejectionMessage(String nameSpaces) {
        String template = "{\"docType\": \"" + PhotoIdDataElements.DOC_TYPE + "\","
                + "\"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\", \"signed\": \"${_signed}\"},"
                + "\"nameSpaces\": " + nameSpaces + "}";
        CertifyException exception = assertThrows(CertifyException.class,
                () -> mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE));
        assertEquals(ErrorConstants.MDOC_TEMPLATE_PROCESSING_FAILED, exception.getErrorCode());
        return exception.getMessage().replaceFirst("^Error processing templated JSON: ", "");
    }

    private String photoIdRejectionMessage(String identifier, Object value) {
        return rejectionMessage(PhotoIdDataElements.DOC_TYPE, PhotoIdDataElements.NAMESPACE, identifier, value);
    }

    @Test
    public void should_digestWithTheConfiguredAlgorithm_when_algorithmIsSha384() throws Exception {
        Map<String, Object> salted = new HashMap<>();
        salted.put(MDL_NAMESPACE, List.of(createSaltedElement(7, "family_name", "Doe")));
        Map<String, Map<Integer, byte[]>> digests = new HashMap<>();

        Map<String, Object> tagged = MDocProcessor.calculateDigests(salted, digests, "SHA-384");

        ByteArrayOutputStream encodedItem = new ByteArrayOutputStream();
        new CborEncoder(encodedItem).encode((DataItem) ((List<?>) tagged.get(MDL_NAMESPACE)).get(0));
        assertArrayEquals(MessageDigest.getInstance("SHA-384").digest(encodedItem.toByteArray()),
                digests.get(MDL_NAMESPACE).get(7));
    }

    @Test
    public void should_reject_when_digestAlgorithmIsNotAllowedByIso() {
        Map<String, Object> salted = new HashMap<>();
        salted.put(MDL_NAMESPACE, List.of(createSaltedElement(0, "family_name", "Doe")));

        assertThrows(IllegalArgumentException.class,
                () -> MDocProcessor.calculateDigests(salted, new HashMap<>(), "SHA-1"));
    }

    @Test
    public void should_assignRandomUniqueDigestIds_when_templateRepeatsOneDigestId() {
        String template = "{\"docType\": \"org.iso.18013.5.1.mDL\"," + getValidityInfoTemplate() + ","
                + "\"nameSpaces\": {\"org.iso.18013.5.1\": ["
                + "  {\"digestID\": 0, \"elementIdentifier\": \"family_name\", \"elementValue\": \"Doe\"},"
                + "  {\"digestID\": 0, \"elementIdentifier\": \"given_name\", \"elementValue\": \"John\"},"
                + "  {\"digestID\": 0, \"elementIdentifier\": \"document_number\", \"elementValue\": \"D1\"},"
                + "  {\"elementIdentifier\": \"issuing_country\", \"elementValue\": \"IN\"}"
                + "]}}";

        List<Object> first = digestIds(mDocProcessor.processTemplatedJson(withMandatoryMdlElements(template), new HashMap<>(), CERT_NOT_BEFORE));
        List<Object> second = digestIds(mDocProcessor.processTemplatedJson(withMandatoryMdlElements(template), new HashMap<>(), CERT_NOT_BEFORE));

        assertEquals("unique within the namespace", MdlDataElements.MANDATORY.size(), first.stream().distinct().count());
        assertNotEquals("drawn again for every mDL", first, second);
    }

    @Test
    public void should_keepDigestId_when_idIsTheLargestThatCanBeDrawn() throws Exception {
        // digestIDs are drawn below Integer.MAX_VALUE; the largest must survive in the item and in the MSO
        int id = Integer.MAX_VALUE - 1;
        Map<String, Object> salted = new HashMap<>();
        salted.put(MDL_NAMESPACE, List.of(createSaltedElement(id, "family_name", "Doe")));
        Map<String, Map<Integer, byte[]>> digests = new HashMap<>();

        Map<String, Object> tagged = MDocProcessor.calculateDigests(salted, digests, "SHA-256");
        ByteString item = (ByteString) ((List<?>) tagged.get(MDL_NAMESPACE)).get(0);
        co.nstant.in.cbor.model.Map decodedItem = (co.nstant.in.cbor.model.Map)
                new CborDecoder(new ByteArrayInputStream(item.getBytes())).decode().get(0);
        assertEquals(new UnsignedInteger(id), decodedItem.get(new UnicodeString("digestID")));

        Map<String, Object> mDoc = new HashMap<>();
        mDoc.put("_holderId", createTestDidJwk());
        mDoc.put("_docType", "org.iso.18013.5.1.mDL");
        byte[] encodedMso = MDocProcessor.encodeToCBOR(mDocProcessor.createMobileSecurityObject(mDoc, digests, "SHA-256"));
        co.nstant.in.cbor.model.Map decodedMso = (co.nstant.in.cbor.model.Map)
                new CborDecoder(new ByteArrayInputStream(encodedMso)).decode().get(0);
        co.nstant.in.cbor.model.Map valueDigests = (co.nstant.in.cbor.model.Map)
                decodedMso.get(new UnicodeString("valueDigests"));
        co.nstant.in.cbor.model.Map namespaceDigests = (co.nstant.in.cbor.model.Map)
                valueDigests.get(new UnicodeString(MDL_NAMESPACE));
        assertArrayEquals(digests.get(MDL_NAMESPACE).get(id),
                ((ByteString) namespaceDigests.get(new UnsignedInteger(id))).getBytes());
    }

    @Test
    public void should_reject_when_templateWritesAValidityInfoDate() {
        for (String name : List.of("signed", "validFrom", "validUntil")) {
            String template = "{\"docType\": \"org.iso.18013.5.1.mDL\","
                    + getValidityInfoTemplate().replace("${_" + name + "}", "2026-07-20T10:00:00Z")
                    + ", \"nameSpaces\": {}}";

            CertifyException exception = assertThrows(CertifyException.class,
                    () -> mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE));
            assertTrue(name, exception.getMessage().contains("validityInfo." + name + " must be ${_" + name + "}"));
        }
    }

    @Test
    public void should_notTag_when_nonDateStringsHandled() throws Exception {
        String[] nonDates = {
                "2025-13-01", // Invalid month
                "2025/01/15", // Wrong format
                "2025-01-15T10:30:00Z", // DateTime
                "not a date",
                "15-01-2025" // Wrong order
        };

        for (String nonDate : nonDates) {
            Map<String, Object> data = new HashMap<>();
            data.put("text", nonDate);

            byte[] encoded = MDocProcessor.encodeToCBOR(data);
            assertNotNull("Should encode non-date: " + nonDate, encoded);

            // These should be encoded as regular strings without tag 1004
            List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(encoded)).decode();
            co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map) decoded.getFirst();
            DataItem textItem = map.get(new UnicodeString("text"));
            assertNotNull("Text item should exist", textItem);
        }
    }

    // ==================== DeviceKeyInfo Tests ====================

    @Test
    public void should_parseCorrectly_when_validDidJwkECProvided() throws Exception {
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
        String encodedKey = Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
        String didJwk = "did:jwk:" + encodedKey;

        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_holderId", didJwk);

        // Test through public method
        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>(), "SHA-256");

        assertNotNull("MSO should not be null", mso);
        assertTrue("MSO should have deviceKeyInfo", mso.containsKey("deviceKeyInfo"));

        Map<String, Object> deviceKeyInfo = (Map<String, Object>) mso.get("deviceKeyInfo");
        assertTrue("DeviceKeyInfo should have deviceKey", deviceKeyInfo.containsKey("deviceKey"));

        Map<Object, Object> deviceKey = (Map<Object, Object>) deviceKeyInfo.get("deviceKey");
        assertEquals("kty should be EC2", 2, deviceKey.get(1));
        assertEquals("crv should be P-256", 1, deviceKey.get(-1));
        assertTrue("Should have x coordinate", deviceKey.containsKey(-2));
        assertTrue("Should have y coordinate", deviceKey.containsKey(-3));
        // ISO/IEC 18013-5, 9.1.5.2: kty, crv, x and y only; no alg (3) and no kid (2)
        assertEquals(Set.of(1, -1, -2, -3), deviceKey.keySet());
    }

    @Test
    public void should_rejectWithInvalidProof_when_ecKeyIsOnP384OrP521() {
        // Only P-256 device keys are supported; RFC 6979 A.2.6 (P-384) and RFC 7515 A.4 (P-521) public keys
        Map<String, String> keys = Map.of(
                "P-384", "{\"kty\":\"EC\",\"crv\":\"P-384\","
                        + "\"x\":\"7DpOQVtOGaRWhhgCn0J_pdqai8SukuAuBqrlKGswDGTe-PDqkFWGYGSiVFFUgLwT\","
                        + "\"y\":\"gBXZty19VyROqO-awMYhiWcIpZNn-d-59UyoSz8cnbEoiyMcOuDU_nNE_SUzJkcg\"}",
                "P-521", "{\"kty\":\"EC\",\"crv\":\"P-521\","
                        + "\"x\":\"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk\","
                        + "\"y\":\"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2\"}");

        keys.forEach((crv, jwk) -> {
            CertifyException exception = assertThrows(CertifyException.class, () -> deviceKeyFor(jwk));

            assertEquals(crv, VCIErrorConstants.INVALID_PROOF, exception.getErrorCode());
            assertEquals("The holder key (kty EC, crv " + crv + ") can't be an mDL device key: "
                    + "it must be an EC key on P-256 (ISO/IEC 18013-5, 9.1.3.4).", exception.getMessage());
        });
    }

    @Test
    public void should_dropAnyFragment_when_didJwkCarriesAFragmentOtherThan0() throws Exception {
        // Only "#0" used to be removed, so any other fragment was decoded as part of the key.
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
        String encodedKey = Base64.getUrlEncoder().withoutPadding().encodeToString(jwkJson.getBytes());

        for (String fragment : List.of("#0", "#key-1", "#")) {
            Map<String, Object> mDocJson = new HashMap<>();
            mDocJson.put("_holderId", "did:jwk:" + encodedKey + fragment);

            Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>(), "SHA-256");
            Map<String, Object> deviceKeyInfo = (Map<String, Object>) mso.get("deviceKeyInfo");
            Map<Object, Object> deviceKey = (Map<Object, Object>) deviceKeyInfo.get("deviceKey");

            assertEquals("crv should be P-256 for fragment " + fragment, 1, deviceKey.get(-1));
        }
    }

    @Test
    public void should_rejectWithInvalidProof_when_ecCoordinateHasLostItsLeadingZero() {
        // a P-256 x of 31 bytes, as when a coordinate starting with a zero byte is encoded without it
        String shortX = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[31]);
        CertifyException exception = assertThrows(CertifyException.class, () -> deviceKeyFor("{\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"x\":\"" + shortX + "\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}"));

        assertEquals(VCIErrorConstants.INVALID_PROOF, exception.getErrorCode());
        assertEquals("The holder key's 'x' member has 31 bytes instead of 32 for crv P-256, so it can't be an mDL device key.",
                exception.getMessage());
    }

    @Test
    public void should_rejectWithInvalidProof_when_ecCurveIsUnsupported() {
        CertifyException exception = assertThrows(CertifyException.class, () -> deviceKeyFor("{\"kty\":\"EC\",\"crv\":\"secp256k1\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}"));

        assertEquals(VCIErrorConstants.INVALID_PROOF, exception.getErrorCode());
        assertTrue(exception.getMessage(), exception.getMessage().contains("kty EC, crv secp256k1"));
    }

    @Test
    public void should_leaveOutKid_when_holderJwkHasAKeyId() throws Exception {
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"kid\":\"test-key-123\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
        String encodedKey = Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
        String didJwk = "did:jwk:" + encodedKey;

        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_holderId", didJwk);

        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>(), "SHA-256");
        Map<String, Object> deviceKeyInfo = (Map<String, Object>) mso.get("deviceKeyInfo");
        Map<Object, Object> deviceKey = (Map<Object, Object>) deviceKeyInfo.get("deviceKey");

        // ISO/IEC 18013-5, 9.1.5.2: the holder JWK's kid is not copied into the device key
        assertFalse("Should not have kid", deviceKey.containsKey(2));
        assertEquals(Set.of(1, -1, -2, -3), deviceKey.keySet());
    }

    @Test
    public void should_rejectWithInvalidProof_when_holderKeyIsEd25519() {
        // RFC 8037, A.2: an Ed25519 public key
        CertifyException exception = assertThrows(CertifyException.class,
                () -> deviceKeyFor("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}"));

        assertEquals(VCIErrorConstants.INVALID_PROOF, exception.getErrorCode());
        assertEquals("The holder key (kty OKP, crv Ed25519) can't be an mDL device key: "
                + "it must be an EC key on P-256 (ISO/IEC 18013-5, 9.1.3.4).", exception.getMessage());
    }

    @Test
    public void should_rejectWithInvalidProof_when_holderKeyIsEd448() {
        String x = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[57]);
        CertifyException exception = assertThrows(CertifyException.class,
                () -> deviceKeyFor("{\"kty\":\"OKP\",\"crv\":\"Ed448\",\"x\":\"" + x + "\"}"));

        assertEquals(VCIErrorConstants.INVALID_PROOF, exception.getErrorCode());
        assertTrue(exception.getMessage(), exception.getMessage().startsWith("The holder key (kty OKP, crv Ed448) can't be an mDL device key"));
    }

    @Test
    public void should_rejectWithInvalidProof_when_holderKeyIsADidKey() {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_holderId", "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169#zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169");

        CertifyException exception = assertThrows(CertifyException.class,
                () -> mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>(), "SHA-256"));

        assertEquals(VCIErrorConstants.INVALID_PROOF, exception.getErrorCode());
        assertEquals("The holder key can't be an mDL device key: it must be sent as a JWK (jwk header or did:jwk), not as a did:key.",
                exception.getMessage());
    }

    @Test
    public void should_rejectWithInvalidProof_when_holderKeyIsRsa() {
        CertifyException exception = assertThrows(CertifyException.class,
                () -> deviceKeyFor("{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri\"}"));

        assertEquals(VCIErrorConstants.INVALID_PROOF, exception.getErrorCode());
        assertTrue(exception.getMessage(), exception.getMessage().startsWith("The holder key (kty RSA) can't be an mDL device key"));
    }

    @Test
    public void should_rejectWithInvalidProof_when_rsaHolderKeyHasACrvThatIsNotAString() {
        // The proof check accepts an RSA did:jwk with any extra crv, so only the device key check sees it
        for (String crv : List.of("5", "{\"a\":1}")) {
            CertifyException exception = assertThrows(CertifyException.class, () -> deviceKeyFor(
                    "{\"kty\":\"RSA\",\"crv\":" + crv + ",\"e\":\"AQAB\",\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri\"}"));

            assertEquals(crv, VCIErrorConstants.INVALID_PROOF, exception.getErrorCode());
            assertTrue(exception.getMessage(), exception.getMessage().startsWith("The holder key (kty RSA) can't be an mDL device key"));
        }
    }

    @Test
    public void should_rejectWithInvalidProof_when_okpCurveIsNotASignatureCurve() {
        // X25519 is a key agreement curve, not one a device can sign with
        CertifyException exception = assertThrows(CertifyException.class,
                () -> deviceKeyFor("{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo\"}"));

        assertEquals(VCIErrorConstants.INVALID_PROOF, exception.getErrorCode());
        assertTrue(exception.getMessage(), exception.getMessage().contains("kty OKP, crv X25519"));
    }

    @Test
    public void should_rejectWithInvalidProof_when_ecKeyHasNoY() {
        CertifyException exception = assertThrows(CertifyException.class, () -> deviceKeyFor("{\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"}"));

        assertEquals(VCIErrorConstants.INVALID_PROOF, exception.getErrorCode());
        assertEquals("The holder key has no 'y' member, so it can't be an mDL device key.", exception.getMessage());
    }

    @Test
    public void should_rejectWithInvalidProof_when_coordinateIsNotBase64url() {
        // A stray character that the proof's signature check skips over, but that isn't base64url
        CertifyException exception = assertThrows(CertifyException.class, () -> deviceKeyFor("{\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"x\":\"MKBCTNIcKU!SDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}"));

        assertEquals(VCIErrorConstants.INVALID_PROOF, exception.getErrorCode());
        assertEquals("The holder key has an invalid 'x' member, so it can't be an mDL device key.", exception.getMessage());
        // the decoding error is kept as the cause, for the server logs
        assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    /** The MSO device key built for a did:jwk holder with the given public JWK. */
    private Map<Object, Object> deviceKeyFor(String jwkJson) throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_holderId", "did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(jwkJson.getBytes()));
        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>(), "SHA-256");
        return (Map<Object, Object>) ((Map<String, Object>) mso.get("deviceKeyInfo")).get("deviceKey");
    }

    // ==================== MSO Structure Tests ====================

    @Test
    public void should_createCompleteStructure_when_validInputProvided() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.iso.18013.5.1.mDL");
        mDocJson.put("_holderId", createTestDidJwk());
        mDocJson.put("validityInfo", expectedValidityInfo);

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<Integer, byte[]> digests = new HashMap<>();
        digests.put(0, new byte[32]);
        digests.put(1, new byte[32]);
        namespaceDigests.put("org.iso.18013.5.1", digests);

        Map<String, Object> result = mDocProcessor.createMobileSecurityObject(mDocJson, namespaceDigests, "SHA-256");

        assertNotNull("MSO should not be null", result);
        assertEquals("Version should match config", "1.0", result.get("version"));
        assertEquals("Digest algorithm should match", "SHA-256", result.get("digestAlgorithm"));
        assertEquals("DocType should match", "org.iso.18013.5.1.mDL", result.get(Constants.DOCTYPE));

        Map<String, Object> actualValidityInfo = (Map<String, Object>) result.get("validityInfo");
        assertEquals(expectedValidityInfo, actualValidityInfo);
        assertNotNull("Should have valueDigests", result.get("valueDigests"));
        assertNotNull("Should have deviceKeyInfo", result.get("deviceKeyInfo"));
    }

    @Test
    public void should_structureCorrectly_when_valueDigestsProcessed() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.test.doc");
        mDocJson.put("_holderId", createTestDidJwk());

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<Integer, byte[]> digests1 = new HashMap<>();
        digests1.put(0, new byte[32]);
        digests1.put(1, new byte[32]);
        namespaceDigests.put("namespace1", digests1);

        Map<Integer, byte[]> digests2 = new HashMap<>();
        digests2.put(0, new byte[32]);
        namespaceDigests.put("namespace2", digests2);

        Map<String, Object> result = mDocProcessor.createMobileSecurityObject(mDocJson, namespaceDigests, "SHA-256");

        Map<String, Object> valueDigests = (Map<String, Object>) result.get("valueDigests");
        assertNotNull("ValueDigests should not be null", valueDigests);

        // nameSpaces is now directly under valueDigests
        assertTrue("Should contain namespace1", valueDigests.containsKey("namespace1"));
        assertTrue("Should contain namespace2", valueDigests.containsKey("namespace2"));

        Map<Integer, byte[]> ns1Digests = (Map<Integer, byte[]>) valueDigests.get("namespace1");
        assertEquals("Namespace1 should have 2 digests", 2, ns1Digests.size());
    }

    @Test
    public void should_addValidityInfo_when_createMobileSecurityObjectIsCalled() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.test.doc");
        mDocJson.put("_holderId", createTestDidJwk());
        mDocJson.put("validityInfo", expectedValidityInfo);

        Map<String, Object> result = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>(), "SHA-256");

        Map<String, Object> resultValidity = (Map<String, Object>) result.get("validityInfo");
        assertEquals(expectedValidityInfo, resultValidity);
    }

    // ==================== COSE Signing Tests ====================

    @Test
    public void should_returnSignedBytes_when_validInputProvided() throws Exception {
        Map<String, Object> mso = new HashMap<>();
        mso.put("version", "1.0");
        mso.put("digestAlgorithm", "SHA-256");

        // Mock the COSE signature service response
        String mockHexSignedData = "d2844341a10126404c504143204f50454e4141";

        CoseSignResponseDto mockResponse = new CoseSignResponseDto();
        mockResponse.setSignedData(mockHexSignedData);

        when(coseSignatureService.coseSign1(any(CoseSignRequestDto.class)))
                .thenReturn(mockResponse);

        byte[] result = mDocProcessor.signMSO(mso, "testApp", "testRef", "ES256");

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);

        // Verify service was called with correct parameters
        ArgumentCaptor<CoseSignRequestDto> captor = ArgumentCaptor.forClass(CoseSignRequestDto.class);
        verify(coseSignatureService).coseSign1(captor.capture());
        CoseSignRequestDto requestDto = captor.getValue();
        assertEquals("Application ID should match", "testApp", requestDto.getApplicationId());
        assertEquals("Reference ID should match", "testRef", requestDto.getReferenceId());
        assertEquals("Algorithm should match", "ES256", requestDto.getAlgorithm());
        assertEquals("Include COSE Tag should match", false, requestDto.getIncludeCOSETag());

        // Assert the request dto payload is B64 encoded - tagged mso #6.24(bstr .cbor mso)
        String payload = requestDto.getPayload();
        try {
            byte[] decodedPayload = Base64.getUrlDecoder().decode(payload);
            assertTrue("Decoded payload should contain data", decodedPayload.length > 0);
            // Verify the decoded payload is a CBOR-encoded tag-24 wrapped ByteString (bstr .cbor mso)
            List<DataItem> cborItems = new CborDecoder(new ByteArrayInputStream(decodedPayload)).decode();
            assertFalse("Should decode to CBOR items", cborItems.isEmpty());
            DataItem item = cborItems.get(0);
            assertTrue("Payload should be a ByteString", item instanceof ByteString);
            assertEquals("Payload should have CBOR tag 24", 24, item.getTag().getValue());
        } catch (IllegalArgumentException e) {
            fail("Payload should be valid Base64 encoded: " + e.getMessage());
        }
    }

    @Test(expected = CertifyException.class)
    public void should_throwException_when_signingFails() throws Exception {
        Map<String, Object> mso = new HashMap<>();
        mso.put("version", "1.0");

        when(coseSignatureService.coseSign1(any(CoseSignRequestDto.class)))
                .thenThrow(new CertifyException("Signing failed"));

        mDocProcessor.signMSO(mso, "app", "ref", "ES256");
    }

    // ==================== IssuerSigned Structure Tests ====================

    @Test
    public void should_createStructure_when_validInputProvided() throws Exception {
        Map<String, Object> processedNamespaces = new HashMap<>();
        List<Object> elements = new ArrayList<>();

        ByteString bs = new ByteString(new byte[]{1, 2, 3});
        bs.setTag(24);
        elements.add(bs);

        processedNamespaces.put("org.iso.18013.5.1", elements);

        // Create a valid COSE_Sign1 structure
        co.nstant.in.cbor.model.Array coseArray = new co.nstant.in.cbor.model.Array();
        coseArray.add(new ByteString(new byte[]{(byte)0xa1, 0x01, 0x26})); // Protected header
        coseArray.add(new co.nstant.in.cbor.model.Map()); // Unprotected header
        coseArray.add(new ByteString(new byte[]{1, 2, 3, 4})); // Payload
        coseArray.add(new ByteString(new byte[]{5, 6, 7, 8})); // Signature

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(coseArray);
        byte[] signedMSO = baos.toByteArray();

        Map<String, Object> result = MDocProcessor.createIssuerSignedStructure(processedNamespaces, signedMSO);

        assertNotNull("Result should not be null", result);
        assertTrue("Should have nameSpaces", result.containsKey("nameSpaces"));
        assertTrue("Should have issuerAuth", result.containsKey("issuerAuth"));

        assertEquals("NameSpaces should match", processedNamespaces, result.get("nameSpaces"));
        assertTrue("IssuerAuth should be DataItem", result.get("issuerAuth") instanceof DataItem);
    }

    @Test
    public void should_handleGracefully_when_emptyNamespacesProvided() throws Exception {
        Map<String, Object> processedNamespaces = new HashMap<>();

        co.nstant.in.cbor.model.Array coseArray = new co.nstant.in.cbor.model.Array();
        coseArray.add(new ByteString(new byte[]{(byte)0xa1, 0x01, 0x26}));
        coseArray.add(new co.nstant.in.cbor.model.Map());
        coseArray.add(new ByteString(new byte[]{1, 2, 3}));
        coseArray.add(new ByteString(new byte[]{4, 5, 6}));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(coseArray);
        byte[] signedMSO = baos.toByteArray();

        Map<String, Object> result = MDocProcessor.createIssuerSignedStructure(processedNamespaces, signedMSO);

        assertNotNull("Result should not be null", result);
        Map<String, Object> nameSpaces = (Map<String, Object>) result.get("nameSpaces");
        assertTrue("NameSpaces should be empty", nameSpaces.isEmpty());
    }

    @Test(expected = IOException.class)
    public void should_throwException_when_invalidCBOREncountered() throws Exception {
        Map<String, Object> processedNamespaces = new HashMap<>();

        // Use bytes that will cause CborException - incomplete CBOR structure
        byte[] invalidCBOR = new byte[]{(byte)0x9f}; // Start of indefinite-length array with no end

        MDocProcessor.createIssuerSignedStructure(processedNamespaces, invalidCBOR);
    }
    // ==================== Integration Tests ====================

    @Test
    public void should_handleCorrectly_when_multipleNamespacesProcessed() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.multi.credential");
        mDocJson.put("_holderId", createTestDidJwk());

        Map<String, Object> nameSpaces = new HashMap<>();
        nameSpaces.put("org.iso.18013.5.1", Collections.singletonList(
                createTestElement(0, "family_name", "Doe")
        ));
        nameSpaces.put("org.mosip.farmer", Collections.singletonList(
                createTestElement(0, "farmer_id", "FARM123")
        ));
        mDocJson.put("nameSpaces", nameSpaces);

        Map<String, Object> saltedNamespaces = MDocProcessor.addRandomSalts(mDocJson);
        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests, "SHA-256");

        assertEquals("Should have 2 namespaces", 2, namespaceDigests.size());
        assertTrue("Should have ISO namespace", namespaceDigests.containsKey("org.iso.18013.5.1"));
        assertTrue("Should have custom namespace", namespaceDigests.containsKey("org.mosip.farmer"));
    }

    // ==================== Edge Cases and Error Handling ====================

    @Test
    public void should_handleGracefully_when_emptyNamespaceEncountered() {
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> nameSpaces = new HashMap<>();
        nameSpaces.put("org.iso.18013.5.1", new ArrayList<>());
        mDocJson.put("nameSpaces", nameSpaces);

        Map<String, Object> result = MDocProcessor.addRandomSalts(mDocJson);

        assertNotNull("Result should not be null", result);
        assertTrue("Should have namespace", result.containsKey("org.iso.18013.5.1"));
        List<?> elements = (List<?>) result.get("org.iso.18013.5.1");
        assertTrue("Elements should be empty", elements.isEmpty());
    }

    @Test
    public void should_handleGracefully_when_emptyElementsEncountered() throws Exception {
        Map<String, Object> saltedNamespaces = new HashMap<>();
        saltedNamespaces.put("org.iso.18013.5.1", new ArrayList<>());

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<String, Object> result = MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests, "SHA-256");

        assertNotNull("Result should not be null", result);
        assertTrue("Should have namespace", result.containsKey("org.iso.18013.5.1"));
        List<?> elements = (List<?>) result.get("org.iso.18013.5.1");
        assertTrue("Elements should be empty", elements.isEmpty());
    }

    @Test
    public void should_handleCorrectly_when_nullValueEncoded() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("nullField", null);
        data.put("normalField", "value");

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);

        // Decode and verify
        List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(result)).decode();
        co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map) decoded.get(0);
        DataItem nullItem = map.get(new UnicodeString("nullField"));
        assertEquals("Null should be encoded as CBOR NULL", SimpleValue.NULL, nullItem);
    }

    @Test
    public void should_handleCorrectly_when_largeNumbersEncoded() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("maxInt", Integer.MAX_VALUE);
        data.put("minInt", Integer.MIN_VALUE);
        data.put("maxLong", Long.MAX_VALUE);
        data.put("minLong", Long.MIN_VALUE);

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);
    }

    @Test
    public void should_handleCorrectly_when_specialFloatsEncoded() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("pi", 3.14159);
        data.put("negative", -2.5);
        data.put("zero", 0.0);

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);
    }

    // ==================== CBOR Type Conversion Tests ====================

    @Test
    public void should_convertCorrectly_when_integerConverted() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("positive", 42);
        data.put("negative", -42);
        data.put("zero", 0);

        byte[] encoded = MDocProcessor.encodeToCBOR(data);
        List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(encoded)).decode();

        assertNotNull("Decoded data should not be null", decoded);
        assertFalse("Should have decoded items", decoded.isEmpty());
    }

    @Test
    public void should_convertCorrectly_when_booleanConverted() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("trueValue", true);
        data.put("falseValue", false);

        byte[] encoded = MDocProcessor.encodeToCBOR(data);
        List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(encoded)).decode();

        co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map) decoded.get(0);
        assertEquals("True should be encoded correctly",
                SimpleValue.TRUE,
                map.get(new UnicodeString("trueValue")));
        assertEquals("False should be encoded correctly",
                SimpleValue.FALSE,
                map.get(new UnicodeString("falseValue")));
    }

    @Test
    public void should_convertToArray_when_listConverted() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("list", Arrays.asList("a", "b", "c"));

        byte[] encoded = MDocProcessor.encodeToCBOR(data);
        List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(encoded)).decode();

        co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map) decoded.get(0);
        DataItem listItem = map.get(new UnicodeString("list"));
        assertTrue("List should be encoded as Array", listItem instanceof Array);
    }

    // ==================== Configuration Tests ====================

    @Test
    public void should_addValidityPeriod_asPer_MdocConfig() throws Exception {
        when(mDocConfig.getValidityPeriodYears()).thenReturn(10);

        String template = "{\"validityInfo\": {\"validFrom\": \"${_validFrom}\",\"signed\": \"${_signed}\", \"validUntil\": \"${_validUntil}\"}, \"docType\": \"${_docType}\"}";
        Map<String, Object> result = mDocProcessor.processTemplatedJson(template, new HashMap<>(), CERT_NOT_BEFORE);

        Map<String, Object> validityInfo = (Map<String, Object>) result.get("validityInfo");
        String validUntil = (String) ((Map<String, Object>) validityInfo.get("validUntil")).get(Constants.__CBOR_VALUE);

        assertNotNull("ValidUntil should be set", validUntil);
        assertEquals("ValidUntil should reflect the configured period",
                "2036-07-20T00:00:00Z", validUntil);
    }

    @Test
    public void should_useMsoVersion_when_mDocConfigApplied() throws Exception {
        when(mDocConfig.getMsoVersion()).thenReturn("2.0");

        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "test");
        mDocJson.put("_holderId", createTestDidJwk());

        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>(), "SHA-256");

        assertEquals("MSO version should match config", "2.0", mso.get("version"));
    }

    @Test
    public void should_declareTheGivenDigestAlgorithm_when_msoIsCreated() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "test");
        mDocJson.put("_holderId", createTestDidJwk());

        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>(), "SHA-512");

        assertEquals("SHA-512", mso.get("digestAlgorithm"));
    }

    @Test
    public void should_digestEveryItemWithTheMsoDigestAlgorithm_when_configuredForSha384() throws Exception {
        MDocConfig sha384Config = new MDocConfig();
        sha384Config.setDigestAlgorithm("SHA-384");
        sha384Config.validate();
        MDocProcessor processor = new MDocProcessor(objectMapper, sha384Config, coseSignatureService, keymanagerService);
        List<Map<String, Object>> elements = List.of(
                createSaltedElement(3, "family_name", "Doe"),
                createSaltedElement(11, "birth_date", "1990-08-25"));
        Map<String, Object> salted = new HashMap<>();
        salted.put(MDL_NAMESPACE, elements);
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", MdlDataElements.DOC_TYPE);
        mDocJson.put("_holderId", createTestDidJwk());

        // As addProof does: the algorithm is read once from the processor's config and given to both
        String digestAlgorithm = processor.getDigestAlgorithm();
        Map<String, Map<Integer, byte[]>> digests = new HashMap<>();
        Map<String, Object> tagged = MDocProcessor.calculateDigests(salted, digests, digestAlgorithm);
        Map<String, Object> mso = processor.createMobileSecurityObject(mDocJson, digests, digestAlgorithm);

        assertEquals("SHA-384", mso.get("digestAlgorithm"));
        Map<?, ?> valueDigests = (Map<?, ?>) ((Map<?, ?>) mso.get("valueDigests")).get(MDL_NAMESPACE);
        assertEquals(elements.size(), valueDigests.size());
        List<?> items = (List<?>) tagged.get(MDL_NAMESPACE);
        for (int i = 0; i < elements.size(); i++) {
            DataItem item = (DataItem) items.get(i);
            assertEquals(24, item.getTag().getValue());
            ByteArrayOutputStream encodedItem = new ByteArrayOutputStream();
            new CborEncoder(encodedItem).encode(item);
            byte[] digest = (byte[]) valueDigests.get(elements.get(i).get("digestID"));
            assertEquals(48, digest.length);
            assertArrayEquals(MessageDigest.getInstance("SHA-384").digest(encodedItem.toByteArray()), digest);
        }
    }

    // ==================== Compliance Tests (ISO 18013-5) ====================

    @Test
    public void should_haveRequiredFields_when_issuerSignedStructureCreated() throws Exception {
        Map<String, Object> processedNamespaces = new HashMap<>();
        processedNamespaces.put("org.iso.18013.5.1", new ArrayList<>());

        byte[] signedMSO = createMockCoseSign1();
        Map<String, Object> issuerSigned = MDocProcessor.createIssuerSignedStructure(processedNamespaces, signedMSO);

        assertTrue("Must have nameSpaces field", issuerSigned.containsKey("nameSpaces"));
        assertTrue("Must have issuerAuth field", issuerSigned.containsKey("issuerAuth"));
        assertEquals("Should only have 2 fields", 2, issuerSigned.size());
    }

    @Test
    public void should_haveRequiredFields_when_msoCreated() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.iso.18013.5.1.mDL");
        mDocJson.put("_holderId", createTestDidJwk());

        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>(), "SHA-256");

        assertTrue("Must have version", mso.containsKey("version"));
        assertTrue("Must have digestAlgorithm", mso.containsKey("digestAlgorithm"));
        assertTrue("Must have valueDigests", mso.containsKey("valueDigests"));
        assertTrue("Must have deviceKeyInfo", mso.containsKey("deviceKeyInfo"));
        assertTrue("Must have docType", mso.containsKey(Constants.DOCTYPE));
        assertTrue("Must have validityInfo", mso.containsKey("validityInfo"));
    }

    @Test
    public void should_structureCorrectly_when_issuerSignedItemCreated() throws Exception {
        Map<String, Object> element = createSaltedElement(0, "family_name", "Doe");

        // Verify element has required fields
        assertTrue("Must have digestID", element.containsKey("digestID"));
        assertTrue("Must have random", element.containsKey("random"));
        assertTrue("Must have elementIdentifier", element.containsKey("elementIdentifier"));
        assertTrue("Must have elementValue", element.containsKey("elementValue"));

        byte[] random = (byte[]) element.get("random");
        assertEquals("Random must be 24 bytes", 24, random.length);
    }

    // ==================== Helper Methods ====================

    private Map<String, Object> createTestMDocJson() {
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> nameSpaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();

        elements.add(createTestElement(0, "family_name", "Doe"));
        elements.add(createTestElement(1, "given_name", "John"));

        nameSpaces.put("org.iso.18013.5.1", elements);
        mDocJson.put("nameSpaces", nameSpaces);

        return mDocJson;
    }

    private Map<String, Object> createTestElement(int digestID, String identifier, Object value) {
        Map<String, Object> element = new HashMap<>();
        element.put("digestID", digestID);
        element.put("elementIdentifier", identifier);
        element.put("elementValue", value);
        return element;
    }

    private Map<String, Object> createSaltedElement(int digestID, String identifier, Object value) {
        Map<String, Object> element = createTestElement(digestID, identifier, value);
        element.put("random", new byte[24]);
        return element;
    }

    private static final String MDL_NAMESPACE = "org.iso.18013.5.1";

    /** The elementValue of an element as calculateDigests encodes it into its IssuerSignedItem. */
    /**
     * The reason processTemplatedJson rejects an mDL whose one element has this value: it fails with
     * mdoc_template_processing_failed, before anything is signed.
     */
    private String rejectionMessage(String identifier, Object value) {
        return rejectionMessage(MdlDataElements.DOC_TYPE, MDL_NAMESPACE, identifier, value);
    }

    /** The same for a document of this docType whose one element, in this namespace, has this value. */
    private String rejectionMessage(String docType, String namespace, String identifier, Object value) {
        Map<String, Object> element = new HashMap<>();
        element.put("elementIdentifier", identifier);
        element.put("elementValue", value);
        Map<String, Object> template = new LinkedHashMap<>();
        template.put("docType", docType);
        template.put("validityInfo", Map.of("signed", "${_signed}", "validFrom", "${_validFrom}", "validUntil", "${_validUntil}"));
        template.put("nameSpaces", Map.of(namespace, List.of(element)));
        String json;
        try {
            json = new ObjectMapper().writeValueAsString(template);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        CertifyException exception = assertThrows(CertifyException.class,
                () -> mDocProcessor.processTemplatedJson(json, new HashMap<>(), CERT_NOT_BEFORE));
        assertEquals(ErrorConstants.MDOC_TEMPLATE_PROCESSING_FAILED, exception.getErrorCode());
        return exception.getMessage().replaceFirst("^Error processing templated JSON: ", "");
    }

    private DataItem encodedElementValue(String namespace, String identifier, Object value) throws Exception {
        Map<String, Object> salted = new HashMap<>();
        salted.put(namespace, List.of(createSaltedElement(0, identifier, value)));
        Map<String, Object> tagged = MDocProcessor.calculateDigests(salted, new HashMap<>(), "SHA-256");
        ByteString item = (ByteString) ((List<?>) tagged.get(namespace)).get(0);
        co.nstant.in.cbor.model.Map element = (co.nstant.in.cbor.model.Map)
                new CborDecoder(new ByteArrayInputStream(item.getBytes())).decode().get(0);
        return element.get(new UnicodeString("elementValue"));
    }

    private static List<Object> digestIds(Map<String, Object> mDoc) {
        List<Map<String, Object>> items = (List<Map<String, Object>>)
                ((Map<String, Object>) mDoc.get("nameSpaces")).get(MDL_NAMESPACE);
        return items.stream().map(item -> item.get("digestID")).toList();
    }

    private String createTestDidJwk() {
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
        return "did:jwk:" + Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
    }

    private String createFullmDLTemplate() {
        return "{"
                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                + getValidityInfoTemplate()+","
                + "\"nameSpaces\": {"
                + "  \"org.iso.18013.5.1\": ["
                + "    {\"digestID\": 0, \"elementIdentifier\": \"family_name\", \"elementValue\": \"Doe\"},"
                + "    {\"digestID\": 1, \"elementIdentifier\": \"given_name\", \"elementValue\": \"John\"},"
                + "    {\"digestID\": 2, \"elementIdentifier\": \"birth_date\", \"elementValue\": \"1990-08-25\"}"
                + "  ]"
                + "}"
                + "}";
    }

    private static String getValidityInfoTemplate() {
        return "\"validityInfo\": {"
                + "  \"validFrom\": \"${_validFrom}\","
                + "  \"validUntil\": \"${_validUntil}\","
                + "  \"signed\": \"${_signed}\""
                + "}";
    }

    private byte[] createMockCoseSign1() throws Exception {
        co.nstant.in.cbor.model.Array coseArray = new co.nstant.in.cbor.model.Array();
        coseArray.add(new ByteString(new byte[]{(byte)0xa1, 0x01, 0x26}));
        coseArray.add(new co.nstant.in.cbor.model.Map());
        coseArray.add(new ByteString(new byte[]{1, 2, 3, 4}));
        coseArray.add(new ByteString(new byte[]{5, 6, 7, 8}));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(coseArray);
        return baos.toByteArray();
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static Stream<Arguments> provideValidityInfoTestCases() {
        return Stream.of(
                Arguments.of(
                        "Missing validFrom field",
                        "{"
                                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                                + "\"holderId\": \"${_holderId}\","
                                + "\"validityInfo\": {"
                                + "\"signed\": \"${_signed}\","
                                + "\"validUntil\": \"${_validUntil}\""
                                + "}"
                                + "}",
                        "Missing validFrom"
                ),
                Arguments.of(
                        "Missing signed field",
                        "{"
                                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                                + "\"holderId\": \"${_holderId}\","
                                + "\"validityInfo\": {"
                                + "\"validFrom\": \"${_validFrom}\","
                                + "\"validUntil\": \"${_validUntil}\""
                                + "}"
                                + "}",
                        "Missing signed"
                ),
                Arguments.of(
                        "Missing validUntil field",
                        "{"
                                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                                + "\"holderId\": \"${_holderId}\","
                                + "\"validityInfo\": {"
                                + "\"validFrom\": \"${_validFrom}\","
                                + "\"signed\": \"${_signed}\""
                                + "}"
                                + "}",
                        "Missing validUntil"
                ),
                Arguments.of(
                        "Validity info entirely missing",
                        "{"
                                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                                + "\"holderId\": \"${_holderId}\""
                                + "}",
                        "Missing validity info"
                )
        );
    }

}
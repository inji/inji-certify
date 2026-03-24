package io.mosip.certify.utils;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.core.dto.CertificateResponseDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.kernel.keymanagerservice.dto.AllCertificatesDataResponseDto;
import io.mosip.kernel.keymanagerservice.dto.CertificateDataResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.test.util.ReflectionTestUtils;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

class DIDDocumentUtilTest {

    @Mock
    private KeymanagerService keymanagerService;

    @Mock
    private CredentialConfigRepository credentialConfigRepository;

    @InjectMocks
    private DIDDocumentUtil didDocumentUtil;

    private static final String DID_URL = "did:example:123";

    private static final String ED25519_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIInbzaZeSXQqEwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV\nBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQK\nDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxMjAwBgNVBAMMKXd3dy5l\neGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VEMjU1MTkpMB4XDTI0MTIyOTA4\nNDY1OFoXDTI3MTIyOTA4NDY1OFowgYYxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJL\nQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwO\nRVhBTVBMRS1DRU5URVIxLTArBgNVBAMMJENFUlRJRllfVkNfU0lHTl9FRDI1NTE5\nLUVEMjU1MTlfU0lHTjAqMAUGAytlcAMhAOX8AiOEEHfyJRKJsjshaJps736mS4zS\ncZVcdUpZpEbxoz8wPTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSVZaEpMbDVgrAy\nZP0ZlwMMXzhS9jAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAAJ4\nPZb+6A5Q5Z2X18B3PLNLs5It2UTu+qL8PhQyoVpEoq44Efl+10qaAiBp7l66sYcf\nsYVhREnJaBACqsEy5cFTZ7j+7Q0GhuepnkYTS9n8DwlOgZgPU0tBBwthbixwFyME\ne2VdtuhyuVnGK8+W6VWMg+lQGyQwPgrzAf6L81bADn+cW6tIVoYd4uuNfoXeM0pL\nTtKMGEyRVdx3Q+wcLEGZXCTYPkUgf+mq8kqf9dCDdDgblPU891msZpg0KGRkLD28\nPF7FPhK0Hq4DzwfhdpiQMe7W19FyH/IXRprJi8LKx4V9Y/rBAvR2loLR0PwVl+VB\nB55c6EluZ6hn9xuwr9w=\n-----END CERTIFICATE-----\n";

    private static final String RSA_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIDxzCCAq+gAwIBAgIIgusG+rdZJWgwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNDEyMjkxMDQ4NDRaFw0yNzEyMjkxMDQ4NDRa\nMIGHMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMS4wLAYD\nVQQDDCV3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9SU0ApMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlkO3CPWJ6Jqu9hzm4Eew7EJSbYCX\n7YGBxYAjRHcLuVgsttyRWUZ3DiRYEoN7bG/jCh7E0Gvv4M5ux4VSw3RJlM+9Tfje\nDUkHdZQ0g5A/r69uyy7+zE8MIM2fXcgwEgIZabm/Zb6+T/K6mSsdPQAHnBe1zXoq\ngTuyTT6pVsHbR0+5ULkhN3BuJyhJ7zw8vC1aiFYA2b05nU7H1Rn+axes8+v80mQS\nGR9iJTrGeYtvz8a+gRhvXmK+h8nhUAJaPHJBacCRMErKvgddWkWBtknJZQmnX0RN\n2IC5+egbE8thCVg8BGBcxOoUBHjHYmus0CZNbTMJQIObL62p7caJHnYtHwIDAQAB\no0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSOi5/6I4vvp8eshKNs\nSwr/BtWM/zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAKHiZu+1\nPjKqvlesbAj4QJkQlpdstz0PgEOnT6+flpcnmyMJj2QvWQbfX8niVWGMIc0HnO+H\ntzc/2oKmO9eQpmdnL4DN7NtuXxbTwTzsGDI934jRZGqHmeCh90j+T7QqSbk+GanC\nOMGFth7aV9j5cDSr7gCIom6N0TEUw/5a3O1+vJCwtQtN29H/+ksro+RYyN4/nbrR\ngix5XRR9VTcsLbM8J8dOxqZxsP+Bgebqp+fqv8QEea4cVYtStEMY6/4M6kKWyL7Q\nsmgwsJ5Vr5w/Y1hOIKaQe9WwWm/T8+byElVgZ/vT5tCYhLxHyBa1vfTgq1FQe5gb\nc6CDSimUO4tcosI=\n-----END CERTIFICATE-----\n";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        LinkedHashMap<String, List<String>> signingMap = new LinkedHashMap<>();
        signingMap.put(SignatureAlg.ED25519_SIGNATURE_SUITE_2018, List.of(JWSAlgorithm.EdDSA));
        signingMap.put(SignatureAlg.ED25519_SIGNATURE_SUITE_2020, List.of(JWSAlgorithm.EdDSA));
        ReflectionTestUtils.setField(didDocumentUtil, "credentialSigningAlgValuesSupportedMap", signingMap);
    }

    @Test
    @SuppressWarnings("unchecked")
    void generateVerificationMethod_forEd25519_2020_setsExpectedType() {
        Map<String, Object> verificationMethod = (Map<String, Object>) ReflectionTestUtils.invokeMethod(
                didDocumentUtil,
                "generateVerificationMethod",
                JWSAlgorithm.EdDSA,
                SignatureAlg.ED25519_SIGNATURE_SUITE_2020,
                ED25519_CERTIFICATE,
                DID_URL,
                "kid-2020"
        );

        assertNotNull(verificationMethod);
        assertEquals("Ed25519VerificationKey2020", verificationMethod.get("type"));
        assertEquals(DID_URL + "#kid-2020", verificationMethod.get("id"));
        assertNotNull(verificationMethod.get("publicKeyMultibase"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void generateVerificationMethod_forEd25519_2018_setsExpectedType() {
        Map<String, Object> verificationMethod = (Map<String, Object>) ReflectionTestUtils.invokeMethod(
                didDocumentUtil,
                "generateVerificationMethod",
                JWSAlgorithm.EdDSA,
                SignatureAlg.ED25519_SIGNATURE_SUITE_2018,
                ED25519_CERTIFICATE,
                DID_URL,
                "kid-2018"
        );

        assertNotNull(verificationMethod);
        assertEquals("Ed25519VerificationKey2018", verificationMethod.get("type"));
        assertEquals(DID_URL + "#kid-2018", verificationMethod.get("id"));
        assertNotNull(verificationMethod.get("publicKeyMultibase"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void generateVerificationMethod_forRsa_setsExpectedType() {
        Map<String, Object> verificationMethod = (Map<String, Object>) ReflectionTestUtils.invokeMethod(
                didDocumentUtil,
                "generateVerificationMethod",
                JWSAlgorithm.RS256,
                null,
                RSA_CERTIFICATE,
                DID_URL,
                "kid-rsa"
        );

        assertNotNull(verificationMethod);
        assertEquals("RsaVerificationKey2018", verificationMethod.get("type"));
        assertEquals(DID_URL + "#kid-rsa", verificationMethod.get("id"));
        assertTrue(((String) verificationMethod.get("publicKeyPem")).startsWith("-----BEGIN PUBLIC KEY-----"));
    }

    @Test
    void generateVerificationMethod_forUnsupportedAlgo_throwsException() {
        CertifyException exception = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(
                        didDocumentUtil,
                        "generateVerificationMethod",
                        "UnsupportedAlgorithm",
                        null,
                        ED25519_CERTIFICATE,
                        DID_URL,
                        "kid-invalid"
                )
        );

        assertEquals(ErrorConstants.UNSUPPORTED_ALGORITHM, exception.getErrorCode());
    }

    @Test
    @SuppressWarnings("unchecked")
    void generateDIDDocument_forEd25519_2020_addsTopLevelContexts() {
        CredentialConfig config = new CredentialConfig();
        config.setKeyManagerAppId("ed-app");
        config.setKeyManagerRefId("ed-ref");
        config.setSignatureCryptoSuite(SignatureAlg.ED25519_SIGNATURE_SUITE_2020);

        CertificateDataResponseDto certificate = new CertificateDataResponseDto();
        certificate.setCertificateData(ED25519_CERTIFICATE);
        certificate.setKeyId("ed-kid");

        when(credentialConfigRepository.findAll()).thenReturn(List.of(config));
        when(keymanagerService.getAllCertificates("ed-app", Optional.of("ed-ref")))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{certificate}));

        Map<String, Object> didDocument = didDocumentUtil.generateDIDDocument(DID_URL);
        List<String> contexts = (List<String>) didDocument.get("@context");
        List<Map<String, Object>> verificationMethods = (List<Map<String, Object>>) didDocument.get("verificationMethod");

        assertEquals(List.of(
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
        ), contexts);
        assertEquals(1, verificationMethods.size());
        assertEquals("Ed25519VerificationKey2020", verificationMethods.get(0).get("type"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void generateDIDDocument_deduplicatesSecurityV1Context() {
        CredentialConfig edConfig = new CredentialConfig();
        edConfig.setKeyManagerAppId("ed-app");
        edConfig.setKeyManagerRefId("ed-ref");
        edConfig.setSignatureCryptoSuite(SignatureAlg.ED25519_SIGNATURE_SUITE_2018);

        CredentialConfig rsaConfig = new CredentialConfig();
        rsaConfig.setKeyManagerAppId("rsa-app");
        rsaConfig.setKeyManagerRefId("rsa-ref");
        rsaConfig.setSignatureAlgo(JWSAlgorithm.RS256);

        CertificateDataResponseDto edCertificate = new CertificateDataResponseDto();
        edCertificate.setCertificateData(ED25519_CERTIFICATE);
        edCertificate.setKeyId("ed-kid");

        CertificateDataResponseDto rsaCertificate = new CertificateDataResponseDto();
        rsaCertificate.setCertificateData(RSA_CERTIFICATE);
        rsaCertificate.setKeyId("rsa-kid");

        when(credentialConfigRepository.findAll()).thenReturn(List.of(edConfig, rsaConfig));
        when(keymanagerService.getAllCertificates("ed-app", Optional.of("ed-ref")))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{edCertificate}));
        when(keymanagerService.getAllCertificates("rsa-app", Optional.of("rsa-ref")))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{rsaCertificate}));

        Map<String, Object> didDocument = didDocumentUtil.generateDIDDocument(DID_URL);
        List<String> contexts = (List<String>) didDocument.get("@context");

        assertEquals(List.of(
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/v1"
        ), contexts);
    }

    @Test
    void getCertificateDataResponseDto_returnsLatestValidCertificate() {
        String appId = "app";
        String refId = "ref";

        CertificateDataResponseDto expired = new CertificateDataResponseDto();
        expired.setCertificateData("expired");
        expired.setExpiryAt(LocalDateTime.now().minusDays(1));
        expired.setKeyId("kid-expired");

        CertificateDataResponseDto valid = new CertificateDataResponseDto();
        valid.setCertificateData("valid");
        valid.setExpiryAt(LocalDateTime.now().plusDays(10));
        valid.setKeyId("kid-valid");

        when(keymanagerService.getAllCertificates(appId, Optional.of(refId)))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{expired, valid}));

        CertificateResponseDTO response = didDocumentUtil.getCertificateDataResponseDto(appId, refId);
        assertEquals("valid", response.getCertificateData());
        assertEquals("kid-valid", response.getKeyId());
    }

    @Test
    void getCertificateDataResponseDto_whenNoCertificates_throwsException() {
        String appId = "app";
        String refId = "ref";
        when(keymanagerService.getAllCertificates(appId, Optional.of(refId)))
                .thenReturn(new AllCertificatesDataResponseDto(null));

        assertThrows(CertifyException.class, () ->
                didDocumentUtil.getCertificateDataResponseDto(appId, refId)
        );
    }
}

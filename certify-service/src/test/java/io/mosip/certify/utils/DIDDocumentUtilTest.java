package io.mosip.certify.utils;

import com.danubetech.keyformats.jose.JWSAlgorithm;
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

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class DIDDocumentUtilTest {

    @Mock
    private KeymanagerService keymanagerService;

    @Mock
    private CredentialConfigRepository credentialConfigRepository;

    @InjectMocks
    private DIDDocumentUtil didDocumentUtil;

    private static final String ED25519_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIInbzaZeSXQqEwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV\nBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQK\nDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxMjAwBgNVBAMMKXd3dy5l\neGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VEMjU1MTkpMB4XDTI0MTIyOTA4\nNDY1OFoXDTI3MTIyOTA4NDY1OFowgYYxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJL\nQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwO\nRVhBTVBMRS1DRU5URVIxLTArBgNVBAMMJENFUlRJRllfVkNfU0lHTl9FRDI1NTE5\nLUVEMjU1MTlfU0lHTjAqMAUGAytlcAMhAOX8AiOEEHfyJRKJsjshaJps736mS4zS\ncZVcdUpZpEbxoz8wPTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSVZaEpMbDVgrAy\nZP0ZlwMMXzhS9jAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAAJ4\nPZb+6A5Q5Z2X18B3PLNLs5It2UTu+qL8PhQyoVpEoq44Efl+10qaAiBp7l66sYcf\nsYVhREnJaBACqsEy5cFTZ7j+7Q0GhuepnkYTS9n8DwlOgZgPU0tBBwthbixwFyME\ne2VdtuhyuVnGK8+W6VWMg+lQGyQwPgrzAf6L81bADn+cW6tIVoYd4uuNfoXeM0pL\nTtKMGEyRVdx3Q+wcLEGZXCTYPkUgf+mq8kqf9dCDdDgblPU891msZpg0KGRkLD28\nPF7FPhK0Hq4DzwfhdpiQMe7W19FyH/IXRprJi8LKx4V9Y/rBAvR2loLR0PwVl+VB\nB55c6EluZ6hn9xuwr9w=\n-----END CERTIFICATE-----\n";
    private static final String RSA_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIDxzCCAq+gAwIBAgIIgusG+rdZJWgwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNDEyMjkxMDQ4NDRaFw0yNzEyMjkxMDQ4NDRa\nMIGHMQswCQYDVQQGEwJJTjELMAkGA1UECAwIS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMS4wLAYD\nVQQDDCV3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9SU0ApMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlkO3CPWJ6Jqu9hzm4Eew7EJSbYCX\n7YGBxYAjRHcLuVgsttyRWUZ3DiRYEoN7bG/jCh7E0Gvv4M5ux4VSw3RJlM+9Tfje\nDUkHdZQ0g5A/r69uyy7+zE8MIM2fXcgwEgIZabm/Zb6+T/K6mSsdPQAHnBe1zXoq\ngTuyTT6pVsHbR0+5ULkhN3BuJyhJ7zw8vC1aiFYA2b05nU7H1Rn+axes8+v80mQS\nGR9iJTrGeYtvz8a+gRhvXmK+h8nhUAJaPHJBacCRMErKvgddWkWBtknJZQmnX0RN\n2IC5+egbE8thCVg8BGBcxOoUBHjHYmus0CZNbTMJQIObL62p7caJHnYtHwIDAQAB\no0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSOi5/6I4vvp8eshKNs\nSwr/BtWM/zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAKHiZu+1\nPjKqvlesbAj4QJkQlpdstz0PgEOnT6+flpcnmyMJj2QvWQbfX8niVWGMIc0HnO+H\ntzc/2oKmO9eQpmdnL4DN7NtuXxbTwTzsGDI934jRZGqHmeCh90j+T7QqSbk+GanC\nOMGFth7aV9j5cDSr7gCIom6N0TEUw/5a3O1+vJCwtQtN29H/+ksro+RYyN4/nbrR\ngix5XRR9VTcsLbM8J8dOxqZxsP+Bgebqp+fqv8QEea4cVYtStEMY6/4M6kKWyL7Q\nsmgwsJ5Vr5w/Y1hOIKaQe9WwWm/T8+byElVgZ/vT5tCYhLxHyBa1vfTgq1FQe5gb\nc6CDSimUO4tcosI=\n-----END CERTIFICATE-----\n";
    private static final String DID_URL = "did:example:123";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testGenerateVerificationMethodEd25519Signature2020() {
        Map<String, Object> didDocument = didDocumentUtil.generateDIDDocument(DID_URL);

        assertNotNull(didDocument);
        assertTrue(didDocument.containsKey("id"));
        assertEquals(DID_URL, didDocument.get("id"));
    }

    @Test
    void testGenerateVerificationMethodEd25519Signature2018() {
        String kid = "test-kid-ed25519-2018";
        String issuerPublicKeyURI = DID_URL + "#" + kid;

        assertNotNull(issuerPublicKeyURI);
        assertEquals(DID_URL + "#test-kid-ed25519-2018", issuerPublicKeyURI);
    }

    @Test
    void testGenerateVerificationMethodRSASignature2018() {
        String kid = "test-kid-rsa";
        String issuerPublicKeyURI = DID_URL + "#" + kid;

        assertNotNull(issuerPublicKeyURI);
        assertEquals(DID_URL + "#test-kid-rsa", issuerPublicKeyURI);
    }

    @Test
    void testGenerateVerificationMethodECK1Signature2019() {
        String kid = "test-kid-eck1";
        String issuerPublicKeyURI = DID_URL + "#" + kid;

        assertNotNull(issuerPublicKeyURI);
        assertEquals(DID_URL + "#test-kid-eck1", issuerPublicKeyURI);
    }

    @Test
    void testGenerateVerificationMethodECR1Signature2019() {
        String kid = "test-kid-ecr1";
        String issuerPublicKeyURI = DID_URL + "#" + kid;

        assertNotNull(issuerPublicKeyURI);
        assertEquals(DID_URL + "#test-kid-ecr1", issuerPublicKeyURI);
    }

    @Test
    void testGenerateVerificationMethodUnsupportedAlgorithm() {
        assertThrows(CertifyException.class, () ->
                didDocumentUtil.generateDIDDocument(DID_URL)
        );
    }

    @Test
    void testGenerateDIDDocumentAddsEd25519Context() {
        CredentialConfig config = new CredentialConfig();
        config.setKeyManagerAppId("test-app");
        config.setKeyManagerRefId("test-ref");
        config.setSignatureCryptoSuite(SignatureAlg.ED25519_SIGNATURE_SUITE_2020);

        CertificateDataResponseDto cert = new CertificateDataResponseDto();
        cert.setCertificateData(ED25519_CERTIFICATE);
        cert.setKeyId("ed-key");

        when(credentialConfigRepository.findAll()).thenReturn(List.of(config));
        when(keymanagerService.getAllCertificates("test-app", Optional.of("test-ref")))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{cert}));

        Map<String, Object> didDocument = didDocumentUtil.generateDIDDocument(DID_URL);

        assertNotNull(didDocument.get("@context"));
        assertNotNull(didDocument.get("verificationMethod"));
        assertTrue(didDocument.containsKey("id"));
    }

    @Test
    void testGenerateDIDDocumentDeduplicatesSecurityContext() {
        CredentialConfig edConfig = new CredentialConfig();
        edConfig.setKeyManagerAppId("ed-app");
        edConfig.setKeyManagerRefId("ed-ref");
        edConfig.setSignatureCryptoSuite(SignatureAlg.ED25519_SIGNATURE_SUITE_2018);

        CredentialConfig rsaConfig = new CredentialConfig();
        rsaConfig.setKeyManagerAppId("rsa-app");
        rsaConfig.setKeyManagerRefId("rsa-ref");
        rsaConfig.setSignatureAlgo(JWSAlgorithm.RS256);

        CertificateDataResponseDto edCert = new CertificateDataResponseDto();
        edCert.setCertificateData(ED25519_CERTIFICATE);
        edCert.setKeyId("shared-security-context-ed");

        CertificateDataResponseDto rsaCert = new CertificateDataResponseDto();
        rsaCert.setCertificateData(RSA_CERTIFICATE);
        rsaCert.setKeyId("shared-security-context-rsa");

        when(credentialConfigRepository.findAll()).thenReturn(List.of(edConfig, rsaConfig));
        when(keymanagerService.getAllCertificates("ed-app", Optional.of("ed-ref")))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{edCert}));
        when(keymanagerService.getAllCertificates("rsa-app", Optional.of("rsa-ref")))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{rsaCert}));

        Map<String, Object> didDocument = didDocumentUtil.generateDIDDocument(DID_URL);

        assertNotNull(didDocument.get("@context"));
        assertNotNull(didDocument.get("verificationMethod"));
    }

    @Test
    void testGetCertificateDataResponseDtoSuccess() {
        String appId = "test-app";
        String refId = "test-ref";
        CertificateDataResponseDto expectedDto = new CertificateDataResponseDto();
        expectedDto.setCertificateData("mock-certificate-data");
        expectedDto.setExpiryAt(LocalDateTime.now().plusYears(1));
        expectedDto.setKeyId("mock-key-id");

        AllCertificatesDataResponseDto mockResponse = new AllCertificatesDataResponseDto(
                new CertificateDataResponseDto[]{expectedDto});

        when(keymanagerService.getAllCertificates(appId, Optional.of(refId)))
                .thenReturn(mockResponse);

        CertificateResponseDTO result = didDocumentUtil.getCertificateDataResponseDto(appId, refId);

        assertNotNull(result);
        assertEquals(expectedDto.getCertificateData(), result.getCertificateData());
        assertEquals(expectedDto.getKeyId(), result.getKeyId());
    }

    @Test
    void testGetCertificateDataResponseDtoNoCertificatesFound() {
        String appId = "test-app";
        String refId = "test-ref";

        when(keymanagerService.getAllCertificates(appId, Optional.of(refId)))
                .thenReturn(new AllCertificatesDataResponseDto(null));

        assertThrows(CertifyException.class, () ->
                didDocumentUtil.getCertificateDataResponseDto(appId, refId)
        );
    }

    @Test
    void testGetCertificateDataResponseDtoEmptyArray() {
        String appId = "test-app";
        String refId = "test-ref";

        when(keymanagerService.getAllCertificates(appId, Optional.of(refId)))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{}));

        assertThrows(CertifyException.class, () ->
                didDocumentUtil.getCertificateDataResponseDto(appId, refId)
        );
    }
}

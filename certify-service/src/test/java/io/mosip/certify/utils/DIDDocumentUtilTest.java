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
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

class DIDDocumentUtilTest {

    @Mock
    KeymanagerService keymanagerService;

    @Mock
    CredentialConfigRepository credentialConfigRepository;

    @InjectMocks
    DIDDocumentUtil didDocumentUtil;

    @BeforeEach
    void setUp() {
        // Initialize mocks before each test
        MockitoAnnotations.openMocks(this);
        LinkedHashMap<String, List<String>> signingMap = new LinkedHashMap<>();
        signingMap.put(SignatureAlg.ED25519_SIGNATURE_SUITE_2018, List.of(JWSAlgorithm.EdDSA));
        signingMap.put(SignatureAlg.ED25519_SIGNATURE_SUITE_2020, List.of(JWSAlgorithm.EdDSA));
        ReflectionTestUtils.setField(didDocumentUtil, "credentialSigningAlgValuesSupportedMap", signingMap);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testGenerateVerificationMethodEd25519Signature2020ViaReflection() {
        String signatureCryptoSuite = JWSAlgorithm.EdDSA;
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIInbzaZeSXQqEwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV\nBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQK\nDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxMjAwBgNVBAMMKXd3dy5l\neGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VEMjU1MTkpMB4XDTI0MTIyOTA4\nNDY1OFoXDTI3MTIyOTA4NDY1OFowgYYxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJL\nQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwO\nRVhBTVBMRS1DRU5URVIxLTArBgNVBAMMJENFUlRJRllfVkNfU0lHTl9FRDI1NTE5\nLUVEMjU1MTlfU0lHTjAqMAUGAytlcAMhAOX8AiOEEHfyJRKJsjshaJps736mS4zS\ncZVcdUpZpEbxoz8wPTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSVZaEpMbDVgrAy\nZP0ZlwMMXzhS9jAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAAJ4\nPZb+6A5Q5Z2X18B3PLNLs5It2UTu+qL8PhQyoVpEoq44Efl+10qaAiBp7l66sYcf\nsYVhREnJaBACqsEy5cFTZ7j+7Q0GhuepnkYTS9n8DwlOgZgPU0tBBwthbixwFyME\ne2VdtuhyuVnGK8+W6VWMg+lQGyQwPgrzAf6L81bADn+cW6tIVoYd4uuNfoXeM0pL\nTtKMGEyRVdx3Q+wcLEGZXCTYPkUgf+mq8kqf9dCDdDgblPU891msZpg0KGRkLD28\nPF7FPhK0Hq4DzwfhdpiQMe7W19FyH/IXRprJi8LKx4V9Y/rBAvR2loLR0PwVl+VB\nB55c6EluZ6hn9xuwr9w=\n-----END CERTIFICATE-----\n";
        String kid = "test-kid-ed25519";
        String didUrl = "did:example:123";
        String issuerPublicKeyURI = didUrl + "#" + kid;

        Map<String, Object> verificationMethod = (Map<String, Object>) ReflectionTestUtils.invokeMethod(
                didDocumentUtil, "generateVerificationMethod", signatureCryptoSuite, certificateString, didUrl, kid);

        assertEquals("z6Mkuw2HXTbK7fXoVbiuriHdm3NDDcVRYWxRymfzdTE6ZWgQ", verificationMethod.get("publicKeyMultibase"));
        assertEquals(didUrl, verificationMethod.get("controller"));
        assertEquals(issuerPublicKeyURI, verificationMethod.get("id"));
        assertEquals("Ed25519VerificationKey2020", verificationMethod.get("type"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testGenerateVerificationMethodEd25519Signature2018ViaReflection() {
        String signatureAlgo = JWSAlgorithm.EdDSA;
        String signatureCryptoSuite = SignatureAlg.ED25519_SIGNATURE_SUITE_2018;
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIInbzaZeSXQqEwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV\nBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQK\nDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxMjAwBgNVBAMMKXd3dy5l\neGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VEMjU1MTkpMB4XDTI0MTIyOTA4\nNDY1OFoXDTI3MTIyOTA4NDY1OFowgYYxCzAJBgNVBAQTAklOMQswCQYDVQQIDAJL\nQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwO\nRVhBTVBMRS1DRU5URVIxLTArBgNVBAMMJENFUlRJRllfVkNfU0lHTl9FRDI1NTE5\nLUVEMjU1MTlfU0lHTjAqMAUGAytlcAMhAOX8AiOEEHfyJRKJsjshaJps736mS4zS\ncZVcdUpZpEbxoz8wPTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSVZaEpMbDVgrAy\nZP0ZlwMMXzhS9jAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAAJ4\nPZb+6A5Q5Z2X18B3PLNLs5It2UTu+qL8PhQyoVpEoq44Efl+10qaAiBp7l66sYcf\nsYVhREnJaBACqsEy5cFTZ7j+7Q0GhuepnkYTS9n8DwlOgZgPU0tBBwthbixwFyME\ne2VdtuhyuVnGK8+W6VWMg+lQGyQwPgrzAf6L81bADn+cW6tIVoYd4uuNfoXeM0pL\nTtKMGEyRVdx3Q+wcLEGZXCTYPkUgf+mq8kqf9dCDdDgblPU891msZpg0KGRkLD28\nPF7FPhK0Hq4DzwfhdpiQMe7W19FyH/IXRprJi8LKx4V9Y/rBAvR2loLR0PwVl+VB\nB55c6EluZ6hn9xuwr9w=\n-----END CERTIFICATE-----\n";
        String kid = "test-kid-ed25519-2018";
        String didUrl = "did:example:123";
        String issuerPublicKeyURI = didUrl + "#" + kid;

        Map<String, Object> verificationMethod = (Map<String, Object>) ReflectionTestUtils.invokeMethod(
                didDocumentUtil, "generateVerificationMethod", signatureAlgo, signatureCryptoSuite, certificateString, didUrl, kid);

        assertEquals("z6Mkuw2HXTbK7fXoVbiuriHdm3NDDcVRYWxRymfzdTE6ZWgQ", verificationMethod.get("publicKeyMultibase"));
        assertEquals(didUrl, verificationMethod.get("controller"));
        assertEquals(issuerPublicKeyURI, verificationMethod.get("id"));
        assertEquals("Ed25519VerificationKey2018", verificationMethod.get("type"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testGenerateVerificationMethodRSASignature2018ViaReflection() {
        String signatureCryptoSuite = JWSAlgorithm.RS256;
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIDxzCCAq+gAwIBAgIIgusG+rdZJWgwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNDEyMjkxMDQ4NDRaFw0yNzEyMjkxMDQ4NDRa\nMIGHMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMS4wLAYD\nVQQDDCV3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9SU0ApMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlkO3CPWJ6Jqu9hzm4Eew7EJSbYCX\n7YGBxYAjRHcLuVgsttyRWUZ3DiRYEoN7bG/jCh7E0Gvv4M5ux4VSw3RJlM+9Tfje\nDUkHdZQ0g5A/r69uyy7+zE8MIM2fXcgwEgIZabm/Zb6+T/K6mSsdPQAHnBe1zXoq\ngTuyTT6pVsHbR0+5ULkhN3BuJyhJ7zw8vC1aiFYA2b05nU7H1Rn+axes8+v80mQS\nGR9iJTrGeYtvz8a+gRhvXmK+h8nhUAJaPHJBacCRMErKvgddWkWBtknJZQmnX0RN\n2IC5+egbE8thCVg8BGBcxOoUBHjHYmus0CZNbTMJQIObL62p7caJHnYtHwIDAQAB\no0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSOi5/6I4vvp8eshKNs\nSwr/BtWM/zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAKHiZu+1\nPjKqvlesbAj4QJkQlpdstz0PgEOnT6+flpcnmyMJj2QvWQbfX8niVWGMIc0HnO+H\ntzc/2oKmO9eQpmdnL4DN7NtuXxbTwTzsGDI934jRZGqHmeCh90j+T7QqSbk+GanC\nOMGFth7aV9j5cDSr7gCIom6N0TEUw/5a3O1+vJCwtQtN29H/+ksro+RYyN4/nbrR\ngix5XRR9VTcsLbM8J8dOxqZxsP+Bgebqp+fqv8QEea4cVYtStEMY6/4M6kKWyL7Q\nsmgwsJ5Vr5w/Y1hOIKaQe9WwWm/T8+byElVgZ/vT5tCYhLxHyBa1vfTgq1FQe5gb\nc6CDSimUO4tcosI=\n-----END CERTIFICATE-----\n";
        String kid = "test-kid-rsa";
        String didUrl = "did:example:123";
        String issuerPublicKeyURI = didUrl + "#" + kid;

        Map<String, Object> verificationMethod = (Map<String, Object>) ReflectionTestUtils.invokeMethod(
                didDocumentUtil, "generateVerificationMethod", signatureCryptoSuite, certificateString, didUrl, kid);

        String publicKeyPem = (String) verificationMethod.get("publicKeyPem");
        assertNotNull(publicKeyPem);
        assertTrue(publicKeyPem.startsWith("-----BEGIN PUBLIC KEY-----"));
        assertTrue(publicKeyPem.endsWith("-----END PUBLIC KEY-----"));

        assertEquals(didUrl, verificationMethod.get("controller"));
        assertEquals(issuerPublicKeyURI, verificationMethod.get("id"));
        assertEquals("RsaVerificationKey2018", verificationMethod.get("type"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testGenerateVerificationMethodECK1Signature2019ViaReflection() {
        String signatureCryptoSuite = JWSAlgorithm.ES256K;
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIDDTCCAfWgAwIBAgIIborC968KpkYwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNTAxMzAwMjI3MzBaFw0yODAxMzAwMjI3MzBa\nMIGbMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMUIwQAYD\nVQQDDDl3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9FQ19LMS1FQ19T\nRUNQMjU2SzFfU0lHTikwVjAQBgcqhkjOPQIBBgUrgQQACgNCAARJNEyvwE3dOioZ\nhZATESbn6aPKJKqr2IazrTT7hQyJlsDAto8mGANVD8+U43h0ZEgGVesuvwuaMgj7\nLnVrRUDzo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBTT5j1MZSg4\nfONSPosQb8SmeZ/OdDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB\nALFGo9udwFWHLrPfQth186H2VuSJ2qNu9vJiNUAgwTAwfM6q2rgpJKywD5Hmqtz1\nioFhr19eXznjQh3m4J75OKQEagmzVPeQvFEtMYuRZAkrX0kLNYhn/5pP8JnQ/W+p\nx+hm+MW0Txn3sX7QWHaSsIMk/vuemQwpjkfoJEzKzqISYlivS6ICCREye93oP57n\n2ZUvm42aKYZ188S9LLmAaXI9vJjXs+oG2G+OGf5P94jDsSvBnIxcU55ztTFogKug\n/N0TUTsda2ljpwhkxDkXYOc1hQTDJD2FIm+pwxwNyv35TYtcUxZhKvgM5AYyQHdG\neRsEPaaCsiGXftuXmdLzMkU=\n-----END CERTIFICATE-----\n";
        String kid = "test-kid-eck1";
        String didUrl = "did:example:123";
        String issuerPublicKeyURI = didUrl + "#" + kid;

        Map<String, Object> verificationMethod = (Map<String, Object>) ReflectionTestUtils.invokeMethod(
                didDocumentUtil, "generateVerificationMethod", signatureCryptoSuite, certificateString, didUrl, kid);

        Map<String,String> publicKeyJwk = (Map<String,String>)verificationMethod.get("publicKeyJwk");
        assertNotNull(publicKeyJwk);
        assertEquals("EC", publicKeyJwk.get("kty"));
        assertEquals("secp256k1", publicKeyJwk.get("crv"));
        assertEquals("STRMr8BN3ToqGYWQExEm5-mjyiSqq9iGs600-4UMiZY", publicKeyJwk.get("x"));
        assertEquals("wMC2jyYYA1UPz5TjeHRkSAZV6y6_C5oyCPsudWtFQPM", publicKeyJwk.get("y"));

        assertEquals(didUrl, verificationMethod.get("controller"));
        assertEquals(issuerPublicKeyURI, verificationMethod.get("id"));
        assertEquals("EcdsaSecp256k1VerificationKey2019", verificationMethod.get("type"));
    }
    @Test
    @SuppressWarnings("unchecked")
    void testGenerateVerificationMethodECR1Signature2019ViaReflection() {
        String signatureCryptoSuite = JWSAlgorithm.ES256;
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIDEDCCAfigAwIBAgIIZ1nHaUeKLDMwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNTA0MDcwMTQ1MzVaFw0yODA0MDYwMTQ1MzVa\nMIGbMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMUIwQAYD\nVQQDDDl3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9FQ19SMS1FQ19T\nRUNQMjU2UjFfU0lHTikwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARnZrptfF7k\nyWism4kK6l8N6K4v8H3FyYzlkDc8/mP55pa+gTUvcEN4DF7jAZntyYUL8GE3Eupf\nd2ZdL7ojg2sgo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBRIWCn1\nRWbTDjYmBJLsnQ5jKyYudzAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQAD\nggEBAIM3Mv1W3N5htKcNEhvtkRYhl0MthNRNzNOuNSRu8VHBgverGE438vdbCQ2f\n/CGBI+Jo2IHdsaFOFGvb6TOOjEZFPgGJyPBK1PGqZc/OiqIcLvPwQ0HVQbp6fgHC\nxocizOAZmrjCQSgQgcDQSuO9tv9JV3Vb7odnPFlbtpREN23AS4KMyVYRm06CrSac\nPW44fSP4GSbWHmgaBvhWxJcXJ/4LpK+UQ1Q0dszm6ofgppd18oSwix90NRDTej7J\nAXmfM3eCvGvMlJC3jHs4EFns9egC16hHqX7INpE1K/ZNyTgHhXpErqaDWw2xkkPC\nvVFPORPyyNumlhL/f36CtutMe2U=\n-----END CERTIFICATE-----\n";
        String kid = "test-kid-ecr1";
        String didUrl = "did:example:123";
        String issuerPublicKeyURI = didUrl + "#" + kid;

        Map<String, Object> verificationMethod = (Map<String, Object>) ReflectionTestUtils.invokeMethod(
                didDocumentUtil, "generateVerificationMethod", signatureCryptoSuite, certificateString, didUrl, kid);

        assertEquals(didUrl, verificationMethod.get("controller"));
        assertEquals("zDnaeXPbtiMpLqxAH31Q9iJgsX7VKtf4z7GQPj5FEGJfBDBGR", verificationMethod.get("publicKeyMultibase"));
        assertEquals(issuerPublicKeyURI, verificationMethod.get("id"));
        assertEquals("EcdsaSecp256r1VerificationKey2019", verificationMethod.get("type"));
    }

    @Test
    void testGenerateVerificationMethodUnsupportedAlgorithmViaReflection() {
        String signatureCryptoSuite = "UnsupportedAlgorithm";
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIInbzaZeSXQqEwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV\nBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQK\nDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxMjAwBgNVBAMMKXd3dy5l\neGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VEMjU1MTkpMB4XDTI0MTIyOTA4\nNDY1OFoXDTI3MTIyOTA4NDY1OFowgYYxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJL\nQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwO\nRVhBTVBMRS1DRU5URVIxLTArBgNVBAMMJENFUlRJRllfVkNfU0lHTl9FRDI1NTE5\nLUVEMjU1MTlfU0lHTjAqMAUGAytlcAMhAOX8AiOEEHfyJRKJsjshaJps736mS4zS\ncZVcdUpZpEbxoz8wPTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSVZaEpMbDVgrAy\nZP0ZlwMMXzhS9jAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAAJ4\nPZb+6A5Q5Z2X18B3PLNLs5It2UTu+qL8PhQyoVpEoq44Efl+10qaAiBp7l66sYcf\nsYVhREnJaBACqsEy5cFTZ7j+7Q0GhuepnkYTS9n8DwlOgZgPU0tBBwthbixwFyME\ne2VdtuhyuVnGK8+W6VWMg+lQGyQwPgrzAf6L81bADn+cW6tIVoYd4uuNfoXeM0pL\nTtKMGEyRVdx3Q+wcLEGZXCTYPkUgf+mq8kqf9dCDdDgblPU891msZpg0KGRkLD28\nPF7FPhK0Hq4DzwfhdpiQMe7W19FyH/IXRprJi8LKx4V9Y/rBAvR2loLR0PwVl+VB\nB55c6EluZ6hn9xuwr9w=\n-----END CERTIFICATE-----\n";
        String kid = "test-kid";
        String didUrl = "did:example:123";

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            ReflectionTestUtils.invokeMethod(didDocumentUtil, "generateVerificationMethod", signatureCryptoSuite, certificateString, didUrl, kid);
        });

        assertEquals(ErrorConstants.UNSUPPORTED_ALGORITHM, exception.getErrorCode());
    }

    @Test
    void testGenerateVerificationMethodWithInvalidCertificateStringViaReflection() {
        String invalidCertificateString = "INVALID_CERTIFICATE";
        String signatureCryptoSuite = SignatureAlg.RSA_SIGNATURE_SUITE_2018;
        String kid = "test-kid";
        String didUrl = "did:example:123";

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            ReflectionTestUtils.invokeMethod(didDocumentUtil, "generateVerificationMethod", signatureCryptoSuite, invalidCertificateString, didUrl, kid);
        });

        assertEquals(ErrorConstants.INVALID_CERTIFICATE, exception.getErrorCode());
    }

    @Test
    @SuppressWarnings("unchecked")
    void testGenerateDIDDocumentAddsEd25519_2020ContextAtTopLevel() {
        CredentialConfig config = new CredentialConfig();
        config.setKeyManagerAppId("test-app");
        config.setKeyManagerRefId("test-ref");
        config.setSignatureCryptoSuite(SignatureAlg.ED25519_SIGNATURE_SUITE_2020);

        CertificateDataResponseDto cert = new CertificateDataResponseDto();
        cert.setCertificateData("-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIInbzaZeSXQqEwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV\nBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQK\nDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxMjAwBgNVBAMMKXd3dy5l\neGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VEMjU1MTkpMB4XDTI0MTIyOTA4\nNDY1OFoXDTI3MTIyOTA4NDY1OFowgYYxCzAJBgNVBAQTAklOMQswCQYDVQQIDAJL\nQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwO\nRVhBTVBMRS1DRU5URVIxLTArBgNVBAMMJENFUlRJRllfVkNfU0lHTl9FRDI1NTE5\nLUVEMjU1MTlfU0lHTjAqMAUGAytlcAMhAOX8AiOEEHfyJRKJsjshaJps736mS4zS\ncZVcdUpZpEbxoz8wPTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSVZaEpMbDVgrAy\nZP0ZlwMMXzhS9jAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAAJ4\nPZb+6A5Q5Z2X18B3PLNLs5It2UTu+qL8PhQyoVpEoq44Efl+10qaAiBp7l66sYcf\nsYVhREnJaBACqsEy5cFTZ7j+7Q0GhuepnkYTS9n8DwlOgZgPU0tBBwthbixwFyME\ne2VdtuhyuVnGK8+W6VWMg+lQGyQwPgrzAf6L81bADn+cW6tIVoYd4uuNfoXeM0pL\nTtKMGEyRVdx3Q+wcLEGZXCTYPkUgf+mq8kqf9dCDdDgblPU891msZpg0KGRkLD28\nPF7FPhK0Hq4DzwfhdpiQMe7W19FyH/IXRprJi8LKx4V9Y/rBAvR2loLR0PwVl+VB\nB55c6EluZ6hn9xuwr9w=\n-----END CERTIFICATE-----\n");
        cert.setKeyId("ed-key");

        when(credentialConfigRepository.findAll()).thenReturn(List.of(config));
        when(keymanagerService.getAllCertificates("test-app", Optional.of("test-ref")))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{cert}));

        Map<String, Object> didDocument = didDocumentUtil.generateDIDDocument("did:example:123");

        List<String> contexts = (List<String>) didDocument.get("@context");
        List<Map<String, Object>> methods = (List<Map<String, Object>>) didDocument.get("verificationMethod");

        assertEquals(List.of("https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"), contexts);
        assertEquals("Ed25519VerificationKey2020", methods.getFirst().get("type"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testGenerateDIDDocumentDeduplicatesSecurityV1ForRsaAndEd25519_2018() {
        CredentialConfig edConfig = new CredentialConfig();
        edConfig.setKeyManagerAppId("ed-app");
        edConfig.setKeyManagerRefId("ed-ref");
        edConfig.setSignatureCryptoSuite(SignatureAlg.ED25519_SIGNATURE_SUITE_2018);

        CredentialConfig rsaConfig = new CredentialConfig();
        rsaConfig.setKeyManagerAppId("rsa-app");
        rsaConfig.setKeyManagerRefId("rsa-ref");
        rsaConfig.setSignatureAlgo(JWSAlgorithm.RS256);

        CertificateDataResponseDto edCert = new CertificateDataResponseDto();
        edCert.setCertificateData("-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIInbzaZeSXQqEwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV\nBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxMjAwBgNVBAMMKXd3dy5l\neGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VEMjU1MTkpMB4XDTI0MTIyOTA4\nNDY1OFoXDTI3MTIyOTA4NDY1OFowgYYxCzAJBgNVBAQTAklOMQswCQYDVQQIDAJL\nQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwO\nRVhBTVBMRS1DRU5URVIxLTArBgNVBAMMJENFUlRJRllfVkNfU0lHTl9FRDI1NTE5\nLUVEMjU1MTlfU0lHTjAqMAUGAytlcAMhAOX8AiOEEHfyJRKJsjshaJps736mS4zS\ncZVcdUpZpEbxoz8wPTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSVZaEpMbDVgrAy\nZP0ZlwMMXzhS9jAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAAJ4\nPZb+6A5Q5Z2X18B3PLNLs5It2UTu+qL8PhQyoVpEoq44Efl+10qaAiBp7l66sYcf\nsYVhREnJaBACqsEy5cFTZ7j+7Q0GhuepnkYTS9n8DwlOgZgPU0tBBwthbixwFyME\ne2VdtuhyuVnGK8+W6VWMg+lQGyQwPgrzAf6L81bADn+cW6tIVoYd4uuNfoXeM0pL\nTtKMGEyRVdx3Q+wcLEGZXCTYPkUgf+mq8kqf9dCDdDgblPU891msZpg0KGRkLD28\nPF7FPhK0Hq4DzwfhdpiQMe7W19FyH/IXRprJi8LKx4V9Y/rBAvR2loLR0PwVl+VB\nB55c6EluZ6hn9xuwr9w=\n-----END CERTIFICATE-----\n");
        edCert.setKeyId("shared-security-context-ed");

        CertificateDataResponseDto rsaCert = new CertificateDataResponseDto();
        rsaCert.setCertificateData("-----BEGIN CERTIFICATE-----\nMIIDxzCCAq+gAwIBAgIIgusG+rdZJWgwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNDEyMjkxMDQ4NDRaFw0yNzEyMjkxMDQ4NDRa\nMIGHMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMS4wLAYD\nVQQDDCV3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9SU0ApMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlkO3CPWJ6Jqu9hzm4Eew7EJSbYCX\n7YGBxYAjRHcLuVgsttyRWUZ3DiRYEoN7bG/jCh7E0Gvv4M5ux4VSw3RJlM+9Tfje\nDUkHdZQ0g5A/r69uyy7+zE8MIM2fXcgwEgIZabm/Zb6+T/K6mSsdPQAHnBe1zXoq\ngTuyTT6pVsHbR0+5ULkhN3BuJyhJ7zw8vC1aiFYA2b05nU7H1Rn+axes8+v80mQS\nGR9iJTrGeYtvz8a+gRhvXmK+h8nhUAJaPHJBacCRMErKvgddWkWBtknJZQmnX0RN\n2IC5+egbE8thCVg8BGBcxOoUBHjHYmus0CZNbTMJQIObL62p7caJHnYtHwIDAQAB\no0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSOi5/6I4vvp8eshKNs\nSwr/BtWM/zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAKHiZu+1\nPjKqvlesbAj4QJkQlpdstz0PgEOnT6+flpcnmyMJj2QvWQbfX8niVWGMIc0HnO+H\ntzc/2oKmO9eQpmdnL4DN7NtuXxbTwTzsGDI934jRZGqHmeCh90j+T7QqSbk+GanC\nOMGFth7aV9j5cDSr7gCIom6N0TEUw/5a3O1+vJCwtQtN29H/+ksro+RYyN4/nbrR\ngix5XRR9VTcsLbM8J8dOxqZxsP+Bgebqp+fqv8QEea4cVYtStEMY6/4M6kKWyL7Q\nsmgwsJ5Vr5w/Y1hOIKaQe9WwWm/T8+byElVgZ/vT5tCYhLxHyBa1vfTgq1FQe5gb\nc6CDSimUO4tcosI=\n-----END CERTIFICATE-----\n");
        rsaCert.setKeyId("shared-security-context-rsa");

        when(credentialConfigRepository.findAll()).thenReturn(List.of(edConfig, rsaConfig));
        when(keymanagerService.getAllCertificates("ed-app", Optional.of("ed-ref")))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{edCert}));
        when(keymanagerService.getAllCertificates("rsa-app", Optional.of("rsa-ref")))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{rsaCert}));

        Map<String, Object> didDocument = didDocumentUtil.generateDIDDocument("did:example:123");

        List<String> contexts = (List<String>) didDocument.get("@context");
        List<Map<String, Object>> methods = (List<Map<String, Object>>) didDocument.get("verificationMethod");

        assertEquals(List.of("https://www.w3.org/ns/did/v1", "https://w3id.org/security/v1"), contexts);
        assertEquals(2, methods.size());
        assertTrue(methods.stream().anyMatch(method -> "Ed25519VerificationKey2018".equals(method.get("type"))));
        assertTrue(methods.stream().anyMatch(method -> "RsaVerificationKey2018".equals(method.get("type"))));
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

        // Case 1: getAllCertificates returns null
        when(keymanagerService.getAllCertificates(appId, Optional.of(refId)))
                .thenReturn(new AllCertificatesDataResponseDto(null));

        CertifyException exception1 = assertThrows(CertifyException.class, () -> {
            didDocumentUtil.getCertificateDataResponseDto(appId, refId);
        });
        assertEquals("No certificates found", exception1.getMessage());

        // Case 2: getAllCertificates returns empty array
        when(keymanagerService.getAllCertificates(appId, Optional.of(refId)))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{}));

        CertifyException exception2 = assertThrows(CertifyException.class, () -> {
            didDocumentUtil.getCertificateDataResponseDto(appId, refId);
        });
        assertEquals("No certificates found", exception2.getMessage());
    }
}

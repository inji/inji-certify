package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.ClaimsDisplayFieldsConfigDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SdJwtCredentialConfigValidatorTest {

    @Test
    void testIsValidCheck_validConfig_returnsTrue() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setCredentialTypes(null);
        config.setContextURLs(null);
        config.setDocType(null);
        config.setCredentialSubjectDefinition(null);
        assertTrue(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_msoMdocClaimsPreset_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setCredentialTypes(null);
        config.setContextURLs(null);
        config.setDocType(null);
        config.setCredentialSubjectDefinition(null);
        config.setMsoMdocClaims(new HashMap<>());
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingSdJwtVct_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct(null);
        config.setSignatureAlgo("algoValue");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptySdJwtVct_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("");
        config.setSignatureAlgo("algoValue");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingSignatureAlgo_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo(null);
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptySignatureAlgo_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_credentialTypeNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setCredentialTypes(java.util.Collections.singletonList("type"));
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_contextNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setContextURLs(java.util.Collections.singletonList("someContextURL.com"));
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_docTypeNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setDocType("docType");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_credentialSubjectNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setCredentialSubjectDefinition(new HashMap<>());
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsConfigAlreadyPresent_present_returnsTrue() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialFormat("format");
        config.setSdJwtVct("vctValue");
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(repo.findByCredentialFormatAndSdJwtVct("format", "vctValue"))
                .thenReturn(Optional.of(new CredentialConfig()));
        assertTrue(SdJwtCredentialConfigValidator.isConfigAlreadyPresent(config, repo));
    }

    @Test
    void testIsConfigAlreadyPresent_notPresent_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialFormat("format");
        config.setSdJwtVct("vctValue");
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(repo.findByCredentialFormatAndSdJwtVct("format", "vctValue"))
                .thenReturn(Optional.empty());
        assertFalse(SdJwtCredentialConfigValidator.isConfigAlreadyPresent(config, repo));
    }

    @Test
    void testIsValidCheck_msoMdocClaimsNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setMsoMdocClaims(new HashMap<>());
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_signatureCryptoSuiteNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setSignatureCryptoSuite("suiteValue");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testValidateSdJwtClaimsAgainstTemplate_validClaims_noException() {
        String template = "{\n" +
                "  \"credentialSubject\": {\n" +
                "    \"id\": \"${_holderId}\",\n" +
                "    \"fullName\": ${fullName},\n" +
                "    \"dateOfBirth\": \"${dateOfBirth}\",\n" +
                "    \"gender\": ${gender}\n" +
                "  }\n" +
                "}";
        String encodedTemplate = Base64.getEncoder().encodeToString(template.getBytes());

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setVcTemplate(encodedTemplate);
        Map<String, ClaimsDisplayFieldsConfigDTO> sdJwtClaims = new HashMap<>();
        sdJwtClaims.put("fullName", new ClaimsDisplayFieldsConfigDTO());
        sdJwtClaims.put("dateOfBirth", new ClaimsDisplayFieldsConfigDTO());
        sdJwtClaims.put("gender", new ClaimsDisplayFieldsConfigDTO());
        config.setSdJwtClaims(sdJwtClaims);

        assertDoesNotThrow(() -> SdJwtCredentialConfigValidator.validateSdJwtClaimsAgainstTemplate(config));
    }

    @Test
    void testValidateSdJwtClaimsAgainstTemplate_invalidClaims_throwsCertifyException() {
        String template = "{\n" +
                "  \"credentialSubject\": {\n" +
                "    \"id\": \"${_holderId}\",\n" +
                "    \"fullName\": ${fullName},\n" +
                "    \"gender\": ${gender}\n" +
                "  }\n" +
                "}";
        String encodedTemplate = Base64.getEncoder().encodeToString(template.getBytes());

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setVcTemplate(encodedTemplate);
        Map<String, ClaimsDisplayFieldsConfigDTO> sdJwtClaims = new HashMap<>();
        sdJwtClaims.put("fullName", new ClaimsDisplayFieldsConfigDTO());
        sdJwtClaims.put("addressLine1", new ClaimsDisplayFieldsConfigDTO()); // not in template
        sdJwtClaims.put("vcVer", new ClaimsDisplayFieldsConfigDTO());        // not in template
        config.setSdJwtClaims(sdJwtClaims);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> SdJwtCredentialConfigValidator.validateSdJwtClaimsAgainstTemplate(config));
        assertEquals(ErrorConstants.INVALID_SD_JWT_CLAIMS, ex.getErrorCode());
    }

    @Test
    void testValidateSdJwtClaimsAgainstTemplate_idFieldIgnored_noException() {
        String template = "{\n" +
                "  \"credentialSubject\": {\n" +
                "    \"id\": \"${_holderId}\",\n" +
                "    \"fullName\": ${fullName}\n" +
                "  }\n" +
                "}";
        String encodedTemplate = Base64.getEncoder().encodeToString(template.getBytes());

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setVcTemplate(encodedTemplate);
        Map<String, ClaimsDisplayFieldsConfigDTO> sdJwtClaims = new HashMap<>();
        sdJwtClaims.put("fullName", new ClaimsDisplayFieldsConfigDTO());
        // "id" is not in sdJwtClaims but should not cause issues since it's removed from templateFields
        config.setSdJwtClaims(sdJwtClaims);

        assertDoesNotThrow(() -> SdJwtCredentialConfigValidator.validateSdJwtClaimsAgainstTemplate(config));
    }

    @Test
    void testValidateSdJwtClaimsAgainstTemplate_noCredentialSubject_invalidClaimsThrows() {
        String template = "{\n" +
                "  \"type\": \"VerifiableCredential\"\n" +
                "}";
        String encodedTemplate = Base64.getEncoder().encodeToString(template.getBytes());

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setVcTemplate(encodedTemplate);
        Map<String, ClaimsDisplayFieldsConfigDTO> sdJwtClaims = new HashMap<>();
        sdJwtClaims.put("fullName", new ClaimsDisplayFieldsConfigDTO());
        config.setSdJwtClaims(sdJwtClaims);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> SdJwtCredentialConfigValidator.validateSdJwtClaimsAgainstTemplate(config));
        assertEquals(ErrorConstants.INVALID_SD_JWT_CLAIMS, ex.getErrorCode());
    }

    @Test
    void testValidateSdJwtClaimsAgainstTemplate_invalidBase64_throwsInvalidVcTemplate() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setVcTemplate("!!!not_valid_base64!!!"); // invalid for both standard and URL-safe decoders
        Map<String, ClaimsDisplayFieldsConfigDTO> sdJwtClaims = new HashMap<>();
        sdJwtClaims.put("fullName", new ClaimsDisplayFieldsConfigDTO());
        config.setSdJwtClaims(sdJwtClaims);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> SdJwtCredentialConfigValidator.validateSdJwtClaimsAgainstTemplate(config));
        assertEquals(ErrorConstants.INVALID_VC_TEMPLATE, ex.getErrorCode());
    }

    @Test
    void testValidateSdJwtClaimsAgainstTemplate_urlSafeBase64_validClaims_noException() {
        String template = "{\n" +
                "  \"credentialSubject\": {\n" +
                "    \"id\": \"${_holderId}\",\n" +
                "    \"fullName\": ${fullName}\n" +
                "  }\n" +
                "}";
        // Use URL-safe Base64 encoder
        String encodedTemplate = Base64.getUrlEncoder().encodeToString(template.getBytes());

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setVcTemplate(encodedTemplate);
        Map<String, ClaimsDisplayFieldsConfigDTO> sdJwtClaims = new HashMap<>();
        sdJwtClaims.put("fullName", new ClaimsDisplayFieldsConfigDTO());
        config.setSdJwtClaims(sdJwtClaims);

        assertDoesNotThrow(() -> SdJwtCredentialConfigValidator.validateSdJwtClaimsAgainstTemplate(config));
    }

    @Test
    void testValidateSdJwtClaimsAgainstTemplate_mixedQuotedAndUnquotedPlaceholders_noException() {
        String template = "{\n" +
                "  \"issuer\": \"${_issuer}\",\n" +
                "  \"credentialSubject\": {\n" +
                "    \"id\": \"${_holderId}\",\n" +
                "    \"gender\": ${gender},\n" +
                "    \"postalCode\": ${postalCode},\n" +
                "    \"fullName\": ${fullName},\n" +
                "    \"dateOfBirth\": \"${dateOfBirth}\",\n" +
                "    \"phone\": \"${phone}\"\n" +
                "  }\n" +
                "}";
        String encodedTemplate = Base64.getEncoder().encodeToString(template.getBytes());

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setVcTemplate(encodedTemplate);
        Map<String, ClaimsDisplayFieldsConfigDTO> sdJwtClaims = new HashMap<>();
        sdJwtClaims.put("gender", new ClaimsDisplayFieldsConfigDTO());
        sdJwtClaims.put("postalCode", new ClaimsDisplayFieldsConfigDTO());
        sdJwtClaims.put("fullName", new ClaimsDisplayFieldsConfigDTO());
        sdJwtClaims.put("dateOfBirth", new ClaimsDisplayFieldsConfigDTO());
        sdJwtClaims.put("phone", new ClaimsDisplayFieldsConfigDTO());
        config.setSdJwtClaims(sdJwtClaims);

        assertDoesNotThrow(() -> SdJwtCredentialConfigValidator.validateSdJwtClaimsAgainstTemplate(config));
    }

    @Test
    void testValidateSdJwtClaimsAgainstTemplate_emptySdJwtClaims_noException() {
        String template = "{\n" +
                "  \"credentialSubject\": {\n" +
                "    \"id\": \"${_holderId}\",\n" +
                "    \"fullName\": ${fullName}\n" +
                "  }\n" +
                "}";
        String encodedTemplate = Base64.getEncoder().encodeToString(template.getBytes());

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setVcTemplate(encodedTemplate);
        config.setSdJwtClaims(new HashMap<>());

        assertDoesNotThrow(() -> SdJwtCredentialConfigValidator.validateSdJwtClaimsAgainstTemplate(config));
    }

    @Test
    void testValidateSdJwtClaimsAgainstTemplate_partialInvalidClaims_throwsWithInvalidClaimNames() {
        String template = "{\n" +
                "  \"credentialSubject\": {\n" +
                "    \"id\": \"${_holderId}\",\n" +
                "    \"fullName\": ${fullName},\n" +
                "    \"email\": \"${email}\"\n" +
                "  }\n" +
                "}";
        String encodedTemplate = Base64.getEncoder().encodeToString(template.getBytes());

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setVcTemplate(encodedTemplate);
        Map<String, ClaimsDisplayFieldsConfigDTO> sdJwtClaims = new HashMap<>();
        sdJwtClaims.put("fullName", new ClaimsDisplayFieldsConfigDTO());
        sdJwtClaims.put("email", new ClaimsDisplayFieldsConfigDTO());
        sdJwtClaims.put("nonExistentField", new ClaimsDisplayFieldsConfigDTO()); // invalid
        config.setSdJwtClaims(sdJwtClaims);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> SdJwtCredentialConfigValidator.validateSdJwtClaimsAgainstTemplate(config));
        assertEquals(ErrorConstants.INVALID_SD_JWT_CLAIMS, ex.getErrorCode());
        assertTrue(ex.getMessage().contains("nonExistentField"));
    }

}

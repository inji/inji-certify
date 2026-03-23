package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTOV2;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MsoMdocCredentialConfigValidatorTest {

    @Test
    void testIsValidCheck_validConfig_returnsTrue() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setCredentialTypes(null);
        config.setContextURLs(null);
        config.setSdJwtVct(null);
        config.setCredentialSubjectDefinition(null);
        assertTrue(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_sdJwtClaimsPresent_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setCredentialTypes(null);
        config.setContextURLs(null);
        config.setSdJwtVct(null);
        config.setCredentialSubjectDefinition(null);
        config.setSdJwtClaims(new HashMap<>());
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingDocType_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType(null);
        config.setSignatureCryptoSuite("suite");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptyDocType_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("");
        config.setSignatureCryptoSuite("suite");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingSignatureCryptoSuite_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureCryptoSuite(null);
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptySignatureCryptoSuite_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_credentialTypeNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setCredentialTypes(List.of("type"));
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_contextNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setContextURLs(List.of("someContext URL"));
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_sdJwtVctNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setSdJwtVct("sdJwtVct");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_credentialSubjectNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setCredentialSubjectDefinition(new HashMap<>());
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsConfigAlreadyPresent_present_returnsTrue() {
        CredentialConfigurationDTO config = Mockito.mock(CredentialConfigurationDTO.class);
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(config.getCredentialFormat()).thenReturn("format");
        Mockito.when(config.getDocType()).thenReturn("docType");
        Mockito.when(repo.findByCredentialFormatAndDocType("format", "docType"))
                .thenReturn(Optional.of(new io.mosip.certify.entity.CredentialConfig()));
        assertTrue(MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(config, repo));
    }

    @Test
    void testIsConfigAlreadyPresent_notPresent_returnsFalse() {
        CredentialConfigurationDTO config = Mockito.mock(CredentialConfigurationDTO.class);
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(config.getCredentialFormat()).thenReturn("format");
        Mockito.when(config.getDocType()).thenReturn("docType");
        Mockito.when(repo.findByCredentialFormatAndDocType("format", "docType"))
                .thenReturn(Optional.empty());
        assertFalse(MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(config, repo));
    }

    @Test
    void testIsValidCheckV2_validConfig_returnsTrue() {
        CredentialConfigurationDTOV2 config = new CredentialConfigurationDTOV2();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setCredentialTypes(null);
        config.setContextURLs(null);
        config.setSdJwtVct(null);
        config.setCredentialSubjectDefinition(null);
        assertTrue(MsoMdocCredentialConfigValidator.isValidCheckV2(config));
    }

    @Test
    void testIsValidCheckV2_sdJwtClaimsPresent_returnsFalse() {
        CredentialConfigurationDTOV2 config = new CredentialConfigurationDTOV2();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setCredentialTypes(null);
        config.setContextURLs(null);
        config.setSdJwtVct(null);
        config.setCredentialSubjectDefinition(null);
        config.setSdJwtClaims(new HashMap<>());
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheckV2(config));
    }

    @Test
    void testIsValidCheckV2_missingDocType_returnsFalse() {
        CredentialConfigurationDTOV2 config = new CredentialConfigurationDTOV2();
        config.setDocType(null);
        config.setSignatureCryptoSuite("suite");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheckV2(config));
    }

    @Test
    void testIsValidCheckV2_emptyDocType_returnsFalse() {
        CredentialConfigurationDTOV2 config = new CredentialConfigurationDTOV2();
        config.setDocType("");
        config.setSignatureCryptoSuite("suite");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheckV2(config));
    }

    @Test
    void testIsValidCheckV2_missingSignatureCryptoSuite_returnsFalse() {
        CredentialConfigurationDTOV2 config = new CredentialConfigurationDTOV2();
        config.setDocType("docType");
        config.setSignatureCryptoSuite(null);
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheckV2(config));
    }

    @Test
    void testIsValidCheckV2_emptySignatureCryptoSuite_returnsFalse() {
        CredentialConfigurationDTOV2 config = new CredentialConfigurationDTOV2();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheckV2(config));
    }

    @Test
    void testIsValidCheckV2_credentialTypeNotNull_returnsFalse() {
        CredentialConfigurationDTOV2 config = new CredentialConfigurationDTOV2();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setCredentialTypes(List.of("type"));
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheckV2(config));
    }

    @Test
    void testIsValidCheckV2_contextNotNull_returnsFalse() {
        CredentialConfigurationDTOV2 config = new CredentialConfigurationDTOV2();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setContextURLs(List.of("someContext URL"));
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheckV2(config));
    }

    @Test
    void testIsValidCheckV2_sdJwtVctNotNull_returnsFalse() {
        CredentialConfigurationDTOV2 config = new CredentialConfigurationDTOV2();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setSdJwtVct("sdJwtVct");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheckV2(config));
    }

    @Test
    void testIsValidCheckV2_credentialSubjectNotNull_returnsFalse() {
        CredentialConfigurationDTOV2 config = new CredentialConfigurationDTOV2();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setCredentialSubjectDefinition(new HashMap<>());
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheckV2(config));
    }

    @Test
    void testIsConfigAlreadyPresentV2_present_returnsTrue() {
        CredentialConfigurationDTOV2 config = Mockito.mock(CredentialConfigurationDTOV2.class);
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(config.getCredentialFormat()).thenReturn("format");
        Mockito.when(config.getDocType()).thenReturn("docType");
        Mockito.when(repo.findByCredentialFormatAndDocType("format", "docType"))
                .thenReturn(Optional.of(new io.mosip.certify.entity.CredentialConfig()));
        assertTrue(MsoMdocCredentialConfigValidator.isConfigAlreadyPresentV2(config, repo));
    }

    @Test
    void testIsConfigAlreadyPresentV2_notPresent_returnsFalse() {
        CredentialConfigurationDTOV2 config = Mockito.mock(CredentialConfigurationDTOV2.class);
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(config.getCredentialFormat()).thenReturn("format");
        Mockito.when(config.getDocType()).thenReturn("docType");
        Mockito.when(repo.findByCredentialFormatAndDocType("format", "docType"))
                .thenReturn(Optional.empty());
        assertFalse(MsoMdocCredentialConfigValidator.isConfigAlreadyPresentV2(config, repo));
    }
}
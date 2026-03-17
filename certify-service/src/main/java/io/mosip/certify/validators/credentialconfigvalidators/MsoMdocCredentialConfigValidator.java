package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTOV2;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;

import java.util.Optional;

public class MsoMdocCredentialConfigValidator {
    public static boolean isValidCheck(CredentialConfigurationDTO credentialConfig) {
        return credentialConfig.getDocType() != null && !credentialConfig.getDocType().isEmpty()
                && credentialConfig.getSignatureCryptoSuite() != null && !credentialConfig.getSignatureCryptoSuite().isEmpty()
                && (credentialConfig.getCredentialTypes() == null || credentialConfig.getCredentialTypes().isEmpty()) && (credentialConfig.getContextURLs() == null || credentialConfig.getContextURLs().isEmpty())
                && credentialConfig.getSdJwtVct() == null && credentialConfig.getCredentialSubjectDefinition() == null
                && credentialConfig.getSdJwtClaims() == null;
    }

    public static boolean isValidCheckV2(CredentialConfigurationDTOV2 credentialConfig) {
        return credentialConfig.getDocType() != null && !credentialConfig.getDocType().isEmpty()
                && credentialConfig.getSignatureCryptoSuite() != null && !credentialConfig.getSignatureCryptoSuite().isEmpty()
                && (credentialConfig.getCredentialTypes() == null || credentialConfig.getCredentialTypes().isEmpty()) && (credentialConfig.getContextURLs() == null || credentialConfig.getContextURLs().isEmpty())
                && credentialConfig.getSdJwtVct() == null && credentialConfig.getCredentialSubjectDefinition() == null
                && credentialConfig.getSdJwtClaims() == null;
    }

    public static boolean isConfigAlreadyPresent(String credentialFormat, String docType,
                                                 CredentialConfigRepository credentialConfigRepository) {
        Optional<CredentialConfig> optional =
                credentialConfigRepository.findByCredentialFormatAndDocType(
                        credentialFormat,
                        docType);

        return optional.isPresent();
    }
}

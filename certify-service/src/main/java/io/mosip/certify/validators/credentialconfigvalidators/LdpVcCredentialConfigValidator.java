package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTOV2;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class LdpVcCredentialConfigValidator {
    public static boolean isValidCheck(CredentialConfigurationDTO credentialConfig) {
        return credentialConfig.getContextURLs() != null && !credentialConfig.getContextURLs().isEmpty()
                && credentialConfig.getCredentialTypes() != null && !credentialConfig.getCredentialTypes().isEmpty()
                && credentialConfig.getSignatureCryptoSuite() != null && !credentialConfig.getSignatureCryptoSuite().isEmpty()
                && credentialConfig.getDocType() == null && credentialConfig.getSdJwtVct() == null
                && credentialConfig.getMsoMdocClaims() == null && credentialConfig.getSdJwtClaims() == null;
    }

    public static boolean isValidCheckV2(CredentialConfigurationDTOV2 credentialConfig) {
        return credentialConfig.getContextURLs() != null && !credentialConfig.getContextURLs().isEmpty()
                && credentialConfig.getCredentialTypes() != null && !credentialConfig.getCredentialTypes().isEmpty()
                && credentialConfig.getSignatureCryptoSuite() != null && !credentialConfig.getSignatureCryptoSuite().isEmpty()
                && credentialConfig.getDocType() == null && credentialConfig.getSdJwtVct() == null
                && credentialConfig.getMsoMdocClaims() == null && credentialConfig.getSdJwtClaims() == null;
    }

    public static boolean isConfigAlreadyPresent(String credentialFormat, List<String> credentialType, List <String> context,
                                        CredentialConfigRepository credentialConfigRepository) {
        Optional<CredentialConfig> optional =
                credentialConfigRepository.findByCredentialFormatAndCredentialTypeAndContext(
                credentialFormat,
                listToCommaSeparatedString(credentialType),
                listToCommaSeparatedString(context));

        return optional.isPresent();
    }

    private static String listToCommaSeparatedString(List<String> list) {
        if (list == null || list.isEmpty()) {
            return null;
        }
        return list.stream()
                .sorted()
                .collect(Collectors.joining(","));
    }

}
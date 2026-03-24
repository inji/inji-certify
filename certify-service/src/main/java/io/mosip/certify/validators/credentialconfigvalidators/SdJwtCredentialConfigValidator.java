package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
public class SdJwtCredentialConfigValidator {
    public static boolean isValidCheck(CredentialConfigurationDTO credentialConfig) {
        return credentialConfig.getSdJwtVct() != null && !credentialConfig.getSdJwtVct().isEmpty()
                && credentialConfig.getSignatureAlgo() != null && !credentialConfig.getSignatureAlgo().isEmpty()
                && (credentialConfig.getCredentialTypes() == null || credentialConfig.getCredentialTypes().isEmpty()) && (credentialConfig.getContextURLs() == null || credentialConfig.getContextURLs().isEmpty())
                && credentialConfig.getDocType() == null && credentialConfig.getCredentialSubjectDefinition() == null &&
                credentialConfig.getMsoMdocClaims() == null && credentialConfig.getSignatureCryptoSuite() == null;
    }

    public static boolean isConfigAlreadyPresent(CredentialConfigurationDTO credentialConfig,
                                                 CredentialConfigRepository credentialConfigRepository) {
        Optional<CredentialConfig> optional =
                credentialConfigRepository.findByCredentialFormatAndSdJwtVct(
                        credentialConfig.getCredentialFormat(),
                        credentialConfig.getSdJwtVct());

        return optional.isPresent();
    }

    public static void validateSdJwtClaimsAgainstTemplate(CredentialConfigurationDTO credentialConfig) {
        try {
            byte[] decodedBytes;
            try {
                decodedBytes = Base64.getDecoder().decode(credentialConfig.getVcTemplate());
            } catch (IllegalArgumentException e) {
                decodedBytes = Base64.getUrlDecoder().decode(credentialConfig.getVcTemplate());
            }

            String decodedTemplate = new String(decodedBytes, StandardCharsets.UTF_8);

            // First replace quoted placeholders like "${field}" → "__placeholder__"
            String sanitizedTemplate = decodedTemplate
                    .replaceAll("\"\\$\\{[^}]+\\}\"", "\"__placeholder__\"");

            // Then replace unquoted placeholders like ${field} → "__placeholder__"
            sanitizedTemplate = sanitizedTemplate
                    .replaceAll("\\$\\{[^}]+\\}", "\"__placeholder__\"");

            org.json.JSONObject templateJson = new org.json.JSONObject(sanitizedTemplate);

            Set<String> templateFields = new HashSet<>();
            Set<String> metadataKeys = new HashSet<>(Arrays.asList(
                    "issuer", "issuanceDate", "expirationDate", "validFrom", "validUntil",
                    "@context", "type", "id", "proof", "vct", "iss", "iat", "exp", "jti",
                    "sub", "cnf", "_issuer"
            ));

            if (templateJson.has("credentialSubject")) {
                org.json.JSONObject credentialSubject = templateJson.getJSONObject("credentialSubject");
                templateFields.addAll(credentialSubject.keySet());
                templateFields.remove("id");
            } else {
                // Flat template — fields are at root level; exclude known metadata keys
                for (String key : templateJson.keySet()) {
                    if (!metadataKeys.contains(key)) {
                        templateFields.add(key);
                    }
                }
            }

            List<String> invalidClaims = credentialConfig.getSdJwtClaims().keySet().stream()
                    .filter(claim -> !templateFields.contains(claim))
                    .collect(java.util.stream.Collectors.toList());

            if (!invalidClaims.isEmpty()) {
                throw new CertifyException(ErrorConstants.INVALID_SD_JWT_CLAIMS,
                        "The following sdJwtClaims are not present in the vcTemplate credentialSubject: " + invalidClaims);
            }
        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to parse vcTemplate for sdJwtClaims validation", e);
            throw new CertifyException(ErrorConstants.INVALID_VC_TEMPLATE,
                    "Failed to parse vcTemplate for sdJWTClaims validation");
        }
    }


}

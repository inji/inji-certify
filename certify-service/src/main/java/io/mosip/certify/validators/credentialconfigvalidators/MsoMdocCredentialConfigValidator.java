package io.mosip.certify.validators.credentialconfigvalidators;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.MdlDataElements;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MsoMdocCredentialConfigValidator {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final Pattern ELEMENT_IDENTIFIER_PATTERN =
            Pattern.compile("\"" + Constants.ELEMENT_IDENTIFIER + "\"\\s*:\\s*\"([^\"]+)\"");

    /**
     * An mdoc's issuerAuth is signed with signatureAlgo alone, so that is mandatory in DataProvider mode,
     * where Certify signs the credential. In VCIssuance mode the plugin signs it, so signatureAlgo is
     * optional. signatureCryptoSuite plays no part in signing an mdoc: it is optional, its value is not
     * validated, and it is not stored.
     */
    public static boolean isValidCheck(CredentialConfigurationDTO credentialConfig, String pluginMode) {
        return credentialConfig.getDocType() != null && !credentialConfig.getDocType().isEmpty()
                && (!"DataProvider".equals(pluginMode) || (credentialConfig.getSignatureAlgo() != null && !credentialConfig.getSignatureAlgo().isEmpty()))
                && (credentialConfig.getCredentialTypes() == null || credentialConfig.getCredentialTypes().isEmpty()) && (credentialConfig.getContextURLs() == null || credentialConfig.getContextURLs().isEmpty())
                && credentialConfig.getSdJwtVct() == null && credentialConfig.getClaims() == null
                && credentialConfig.getSdJwtClaims() == null;
    }

    /**
     * An mDL template must declare every ISO/IEC 18013-5 Table 5 mandatory element in the
     * org.iso.18013.5.1 namespace. Checked in DataProvider mode only, where Certify builds the mDL
     * from the template; in VCIssuance mode the plugin builds it.
     *
     * @return the mandatory elements the template does not declare, empty when none are missing
     */
    public static List<String> findMissingMdlElements(CredentialConfigurationDTO credentialConfig, String pluginMode) {
        if (!"DataProvider".equals(pluginMode) || !MdlDataElements.DOC_TYPE.equals(credentialConfig.getDocType())) {
            return List.of();
        }
        Set<String> declared = declaredMdlElements(decodeTemplate(credentialConfig.getVcTemplate()));
        return MdlDataElements.MANDATORY.stream().filter(element -> !declared.contains(element)).toList();
    }

    private static Set<String> declaredMdlElements(String template) {
        Set<String> declared = new HashSet<>();
        if (template == null || template.isBlank()) {
            return declared;
        }
        try {
            JsonNode items = OBJECT_MAPPER.readTree(template).path(Constants.NAMESPACES).path(MdlDataElements.NAMESPACE);
            items.forEach(item -> declared.add(item.path(Constants.ELEMENT_IDENTIFIER).asText()));
        } catch (JsonProcessingException e) {
            // A template using Velocity directives is not JSON until rendered: read the
            // identifiers from its text instead.
            Matcher matcher = ELEMENT_IDENTIFIER_PATTERN.matcher(template);
            while (matcher.find()) {
                declared.add(matcher.group(1));
            }
        }
        return declared;
    }

    /** The template as stored is base64; raw JSON is accepted as well. */
    private static String decodeTemplate(String vcTemplate) {
        if (vcTemplate == null) {
            return null;
        }
        try {
            return new String(Base64.getDecoder().decode(vcTemplate.trim()), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return vcTemplate;
        }
    }

    public static boolean isConfigAlreadyPresent(CredentialConfigurationDTO credentialConfig,
                                                 CredentialConfigRepository credentialConfigRepository) {
        Optional<CredentialConfig> optional =
                credentialConfigRepository.findByCredentialFormatAndDocType(
                        credentialConfig.getCredentialFormat(),
                        credentialConfig.getDocType());

        return optional.isPresent();
    }
}
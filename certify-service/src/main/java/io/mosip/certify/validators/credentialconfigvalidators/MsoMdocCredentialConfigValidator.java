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
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class MsoMdocCredentialConfigValidator {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

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
     * from the template; in VCIssuance mode the plugin builds it. A template whose mDL identifiers
     * are only known once Velocity renders it (a directive such as #foreach, or an identifier or
     * namespace that is a reference such as ${element.id}) can't be checked here; MDocProcessor
     * checks the rendered mDL at issuance instead.
     *
     * @return the mandatory elements the template does not declare, empty when none are missing
     */
    public static List<String> findMissingMdlElements(CredentialConfigurationDTO credentialConfig, String pluginMode) {
        if (!"DataProvider".equals(pluginMode) || !MdlDataElements.DOC_TYPE.equals(credentialConfig.getDocType())) {
            return List.of();
        }
        Optional<Set<String>> declared = declaredMdlElements(decodeTemplate(credentialConfig.getVcTemplate()));
        if (declared.isEmpty()) {
            return List.of();
        }
        return MdlDataElements.missingMandatory(declared.get());
    }

    /** The identifiers in the mDL namespace, or empty when they are only known after rendering. */
    private static Optional<Set<String>> declaredMdlElements(String template) {
        Set<String> declared = new HashSet<>();
        if (template == null || template.isBlank()) {
            return Optional.of(declared);
        }
        JsonNode namespaces;
        try {
            namespaces = OBJECT_MAPPER.readTree(template).path(Constants.NAMESPACES);
        } catch (JsonProcessingException e) {
            // Velocity directives make the template invalid JSON until it is rendered.
            return Optional.empty();
        }
        if (!namespaces.has(MdlDataElements.NAMESPACE)) {
            // A namespace written as a reference such as ${namespace} may render as the mDL one.
            for (Iterator<String> names = namespaces.fieldNames(); names.hasNext(); ) {
                if (names.next().contains("$")) {
                    return Optional.empty();
                }
            }
        }
        for (JsonNode item : namespaces.path(MdlDataElements.NAMESPACE)) {
            String identifier = item.path(Constants.ELEMENT_IDENTIFIER).asText();
            if (identifier.contains("$")) {
                return Optional.empty();
            }
            declared.add(identifier);
        }
        return Optional.of(declared);
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
package io.mosip.certify.validators.credentialconfigvalidators;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.MDocProcessor;
import io.mosip.certify.utils.MdlDataElements;
import lombok.extern.slf4j.Slf4j;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Slf4j
public class MsoMdocCredentialConfigValidator {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /**
     * The JSON escape of the NUL character, which starts the string an unquoted reference such as
     * ${drivingPrivileges} is parsed as. A template's own strings never start with NUL, so a value that
     * does was written without quotes.
     */
    private static final String UNQUOTED_REFERENCE_MARKER = "\\u0000";

    /** The validityInfo dates Certify sets at issuance, each with the placeholder the template must leave. */
    private static final List<Map.Entry<String, String>> VALIDITY_INFO_PLACEHOLDERS = List.of(
            Map.entry(Constants.SIGNED, "${_signed}"),
            Map.entry(VCDM2Constants.VALID_FROM, "${_validFrom}"),
            Map.entry(VCDM2Constants.VALID_UNTIL, "${_validUntil}"));

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
     * from the template; in VCIssuance mode the plugin builds it. A value may be an unquoted reference
     * such as "elementValue": ${drivingPrivileges}. A template whose mDL identifiers are only known once
     * Velocity renders it (a directive such as #foreach, or nameSpaces, the mDL namespace, its element list,
     * an element or an identifier that is a reference such as ${elements} or ${element.id}) is not checked.
     *
     * @return the mandatory elements the template does not declare, empty when none are missing
     * @throws CertifyException when the template declares an mDL element identifier twice
     */
    public static List<String> findMissingMdlElements(CredentialConfigurationDTO credentialConfig, String pluginMode) {
        if (!"DataProvider".equals(pluginMode) || !MdlDataElements.DOC_TYPE.equals(credentialConfig.getDocType())) {
            return List.of();
        }
        Optional<Set<String>> declared = declaredMdlElements(TemplateDecoder.decodeVcTemplate(credentialConfig.getVcTemplate()));
        if (declared.isEmpty()) {
            return List.of();
        }
        return MdlDataElements.missingMandatory(declared.get());
    }

    /**
     * ISO/IEC 18013-5, 9.1.2.4: Certify sets the validityInfo dates of an mdoc it signs, so in DataProvider
     * mode every mso_mdoc template must leave validityInfo.signed, validFrom and validUntil as the
     * placeholders ${_signed}, ${_validFrom} and ${_validUntil}, written as JSON strings. A template that
     * can't be parsed before Velocity renders it (a directive such as #if) is not checked here; issuance
     * checks it.
     *
     * @throws CertifyException naming the first validityInfo field that is missing or not its placeholder
     */
    public static void requireValidityInfoPlaceholders(CredentialConfigurationDTO credentialConfig, String pluginMode) {
        if (!"DataProvider".equals(pluginMode)) {
            return;
        }
        Optional<JsonNode> template = parseTemplate(TemplateDecoder.decodeVcTemplate(credentialConfig.getVcTemplate()));
        if (template.isEmpty()) {
            return;
        }
        JsonNode validityInfo = template.get().path(Constants.VALIDITY_INFO);
        if (!validityInfo.isObject()) {
            throw new CertifyException(ErrorConstants.MDOC_TEMPLATE_PROCESSING_FAILED,
                    "An mso_mdoc template must have validityInfo with signed, validFrom and validUntil set to "
                            + "${_signed}, ${_validFrom} and ${_validUntil}; Certify sets the validityInfo dates at issuance.");
        }
        for (Map.Entry<String, String> field : VALIDITY_INFO_PLACEHOLDERS) {
            JsonNode value = validityInfo.path(field.getKey());
            if (!value.isTextual() || !field.getValue().equals(value.asText())) {
                throw new CertifyException(ErrorConstants.MDOC_TEMPLATE_PROCESSING_FAILED,
                        "validityInfo." + field.getKey() + " must be \"" + field.getValue()
                                + "\"; Certify sets the validityInfo dates at issuance.");
            }
        }
    }

    /**
     * An mso_mdoc template may tag a value itself, as {"__cbor_tag": 1004, "__cbor_value": "2024-06-15"},
     * which is how a full-date or tdate is written outside the mDL namespace. In DataProvider mode, wherever
     * it appears, the tag must be the integer 1004 (full-date, RFC 8943) or 0 (tdate, RFC 8949); Certify
     * encodes no other. The tagged value is checked at issuance, once rendered. A template that can't be
     * parsed before Velocity renders it is not checked here; issuance checks it.
     *
     * @throws CertifyException naming where the first other tag is
     */
    public static void requireSupportedCborTags(CredentialConfigurationDTO credentialConfig, String pluginMode) {
        if ("DataProvider".equals(pluginMode)) {
            parseTemplate(TemplateDecoder.decodeVcTemplate(credentialConfig.getVcTemplate()))
                    .ifPresent(template -> requireSupportedCborTags(template, ""));
        }
    }

    private static void requireSupportedCborTags(JsonNode node, String path) {
        if (node.isObject()) {
            JsonNode tag = node.get(Constants.__CBOR_TAG);
            if (tag != null && !(tag.isInt() && (tag.intValue() == MDocProcessor.FULL_DATE_TAG || tag.intValue() == MDocProcessor.TDATE_TAG))) {
                throw new CertifyException(ErrorConstants.MDOC_TEMPLATE_PROCESSING_FAILED,
                        "The __cbor_tag at " + (path.isEmpty() ? "the top of the template" : path)
                                + " must be the integer 0 (tdate) or 1004 (full-date).");
            }
            node.fields().forEachRemaining(field ->
                    requireSupportedCborTags(field.getValue(), path.isEmpty() ? field.getKey() : path + "." + field.getKey()));
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                requireSupportedCborTags(node.get(i), path + "[" + i + "]");
            }
        }
    }

    /** The identifiers in the mDL namespace, or empty when they are only known after rendering. */
    private static Optional<Set<String>> declaredMdlElements(String template) {
        Set<String> declared = new HashSet<>();
        if (template == null || template.isBlank()) {
            return Optional.of(declared);
        }
        Optional<JsonNode> parsed = parseTemplate(template);
        if (parsed.isEmpty()) {
            return Optional.empty();
        }
        JsonNode namespaces = parsed.get().path(Constants.NAMESPACES);
        if (isUnquotedReference(namespaces)) {
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
        JsonNode items = namespaces.path(MdlDataElements.NAMESPACE);
        if (isUnquotedReference(items)) {
            return Optional.empty();
        }
        for (JsonNode item : items) {
            if (isUnquotedReference(item)) {
                return Optional.empty();
            }
            String identifier = item.path(Constants.ELEMENT_IDENTIFIER).asText();
            if (identifier.contains("$")) {
                return Optional.empty();
            }
            if (!declared.add(identifier)) {
                // A verifier asking for this element could not tell which of the two values is the mDL's.
                throw new CertifyException(ErrorConstants.MDOC_TEMPLATE_PROCESSING_FAILED,
                        "Duplicate mDL element identifier: " + identifier + ".");
            }
        }
        return Optional.of(declared);
    }

    private static boolean isUnquotedReference(JsonNode node) {
        return node.isTextual() && node.asText().startsWith("\0");
    }

    /**
     * The template parsed as JSON, with unquoted references quoted (see quoteUnquotedReferences). Empty
     * when there is no template or it is only JSON once Velocity renders it, for example because of a
     * directive such as #if or #foreach.
     */
    private static Optional<JsonNode> parseTemplate(String template) {
        if (template == null || template.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(OBJECT_MAPPER.readTree(quoteUnquotedReferences(template)));
        } catch (JsonProcessingException e) {
            log.debug("mso_mdoc template is not JSON before rendering; Add/Update checks are skipped: {}",
                    e.getOriginalMessage());
            return Optional.empty();
        }
    }

    /**
     * The template with each Velocity reference written outside a JSON string (${...} or $!{...}, such as
     * "elementValue": ${drivingPrivileges}) quoted as UNQUOTED_REFERENCE_MARKER followed by the text of that
     * reference, so that a template whose values are rendered as JSON parses. A quoted reference still
     * contains $, so an identifier or namespace written as one is still found, and the marker keeps an
     * unquoted ${_signed} apart from the string "${_signed}".
     */
    private static String quoteUnquotedReferences(String template) {
        StringBuilder quoted = new StringBuilder(template.length());
        boolean inString = false;
        for (int i = 0; i < template.length(); i++) {
            char c = template.charAt(i);
            if (inString) {
                quoted.append(c);
                if (c == '\\' && i + 1 < template.length()) {
                    quoted.append(template.charAt(++i));
                } else if (c == '"') {
                    inString = false;
                }
            } else if (c == '"') {
                inString = true;
                quoted.append(c);
            } else if (c == '$' && (template.startsWith("{", i + 1) || template.startsWith("!{", i + 1))) {
                int end = endOfReference(template, template.indexOf('{', i));
                if (end < 0) {
                    // An unterminated reference is left as it is, and the template does not parse.
                    quoted.append(template, i, template.length());
                    break;
                }
                String reference = template.substring(i, end + 1);
                quoted.append('"').append(UNQUOTED_REFERENCE_MARKER)
                        .append(reference.replace("\\", "\\\\").replace("\"", "\\\"")).append('"');
                i = end;
            } else {
                quoted.append(c);
            }
        }
        return quoted.toString();
    }

    /** The index of the } that closes the { at open, or -1 when there is none. */
    private static int endOfReference(String template, int open) {
        int depth = 0;
        for (int i = open; i < template.length(); i++) {
            char c = template.charAt(i);
            if (c == '{') {
                depth++;
            } else if (c == '}' && --depth == 0) {
                return i;
            }
        }
        return -1;
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
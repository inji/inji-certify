package io.mosip.certify.validators.credentialconfigvalidators;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Decodes a credential configuration's vcTemplate for the validators. */
final class TemplateDecoder {

    private TemplateDecoder() {
    }

    /**
     * Decodes a Base64-encoded VC template string, the form it is stored in.
     * If the template is already raw JSON or invalid Base64, returns the raw input.
     *
     * @param vcTemplate The input VC template string (Base64 or raw JSON)
     * @return Decoded UTF-8 JSON string or raw input
     */
    static String decodeVcTemplate(String vcTemplate) {
        if (vcTemplate == null || vcTemplate.isEmpty()) {
            return vcTemplate;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(vcTemplate.trim());
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ignored) {
            // If not base64 encoded or fails decoding, return raw vcTemplate
            return vcTemplate;
        }
    }
}

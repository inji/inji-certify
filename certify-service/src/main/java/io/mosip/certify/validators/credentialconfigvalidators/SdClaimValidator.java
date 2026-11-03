package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.utils.SDJsonUtils;
import org.apache.commons.codec.binary.Base64;

/**
 * Validates the selective disclosure paths configured in {@code sdClaim} when a dc+sd-jwt credential
 * configuration is added or updated. Other formats do not use {@code sdClaim}, so they are not checked.
 */
public class SdClaimValidator {

    private SdClaimValidator() {
    }

    /**
     * Every entry must be a well formed selective disclosure path. In DataProvider mode, where the credential
     * is rendered from the template, each path must also be declared in it, or VC fetch fails it for every
     * holder. A malformed entry is reported before an undeclared one.
     *
     * @param sdClaim    the comma separated paths as configured, or null when the configuration declares no
     *                   selective disclosure
     * @param vcTemplate the base64 encoded template, as the configuration stores it
     * @param pluginMode the deployment's plugin mode
     * @throws CertifyException with {@link ErrorConstants#INVALID_SD_CLAIM} for the first entry that is blank,
     *                          not a well formed selective disclosure path, or not declared in the template
     */
    public static void validateSdClaim(String sdClaim, String vcTemplate, String pluginMode) {
        if (sdClaim == null) {
            return;
        }
        validatePathSyntax(sdClaim);
        if ("DataProvider".equals(pluginMode)) {
            validatePathsInTemplate(sdClaim, vcTemplate);
        }
    }

    private static void validatePathSyntax(String sdClaim) {
        // The -1 limit keeps trailing empty entries. A plain split(",") reads "$.fullName," as one valid
        // path and "," as no paths at all, so both would pass.
        for (String entry : sdClaim.split(",", -1)) {
            if (entry.isBlank()) {
                throw new CertifyException(ErrorConstants.INVALID_SD_CLAIM,
                        "The sdClaim '" + sdClaim + "' contains a blank entry.");
            }
            if (!SDJsonUtils.isPathSyntaxValid(entry)) {
                throw new CertifyException(ErrorConstants.INVALID_SD_CLAIM,
                        "The sdClaim entry '" + entry.trim() + "' is not a valid selective disclosure path,"
                                + " such as $.fullName, $.address.region, $.phoneNumbers[0] or $.phoneNumbers[*].");
            }
        }
    }

    private static void validatePathsInTemplate(String sdClaim, String vcTemplate) {
        if (vcTemplate == null) {
            return;
        }
        // Decoded as VelocityTemplatingEngineImpl.getTemplate does, so this agrees with the check at VC fetch.
        String template = new String(Base64.decodeBase64(vcTemplate));
        for (String entry : sdClaim.split(",", -1)) {
            String path = entry.trim();
            // The root names no field, so there is nothing to look up. VC fetch accepts it.
            if (path.equals("$")) {
                continue;
            }
            if (!SDJsonUtils.isPathInTemplate(template, path)) {
                throw new CertifyException(ErrorConstants.INVALID_SD_CLAIM,
                        "The sdClaim entry '" + path + "' is not declared in the vcTemplate.");
            }
        }
    }
}

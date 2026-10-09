package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.utils.SDJsonUtils;

/**
 * Validates the selective disclosure paths configured in {@code sdClaim} when a credential
 * configuration is added or updated.
 */
public class SdClaimValidator {

    private SdClaimValidator() {
    }

    /**
     * @param sdClaim the comma separated selective disclosure paths as configured, or null when the
     *                configuration declares no selective disclosure
     * @throws CertifyException if any entry is blank or is not a well formed selective disclosure path
     */
    public static void validateSdClaim(String sdClaim) {
        if (sdClaim == null) {
            return;
        }

        for (String path : sdClaim.split(",", -1)) {
            if (!SDJsonUtils.isPathSyntaxValid(path)) {
                throw new CertifyException(ErrorConstants.INVALID_SD_CLAIM,
                        "The sd_claim entry '" + path + "' is not a valid selective disclosure path. "
                                + "Each entry must be a path such as $.fullName, $.address.region, "
                                + "$.phoneNumbers[0] or $.phoneNumbers[*].");
            }
        }
    }
}

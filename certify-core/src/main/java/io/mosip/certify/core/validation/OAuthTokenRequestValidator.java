/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.validation;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.OAuthTokenRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.util.StringUtils;

public class OAuthTokenRequestValidator implements ConstraintValidator<ValidOAuthTokenRequest, OAuthTokenRequest> {
    
    private static final String AUTHORIZATION_CODE_GRANT = "authorization_code";

    @Override
    public boolean isValid(OAuthTokenRequest value, ConstraintValidatorContext context) {
        if (value == null) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("OAuth token request is required")
                   .addConstraintViolation();
            return false;
        }

        // Validate grant_type
        if (!StringUtils.hasText(value.getGrant_type())) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("grant_type is required")
                   .addPropertyNode("grant_type")
                   .addConstraintViolation();
            return false;
        }

        String grantType = value.getGrant_type();

        // Validate based on grant type
        if (AUTHORIZATION_CODE_GRANT.equals(grantType)) {
            return validateAuthorizationCodeGrant(value, context);
        } else if (Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE.equals(grantType)) {
            return validatePreAuthorizedCodeGrant(value, context);
        } else {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Unsupported grant_type: " + grantType +
                    ". Supported types: 'authorization_code', 'urn:ietf:params:oauth:grant-type:pre-authorized_code'")
                   .addPropertyNode("grant_type")
                   .addConstraintViolation();
            return false;
        }
    }

    private boolean validateAuthorizationCodeGrant(OAuthTokenRequest value, ConstraintValidatorContext context) {
        boolean hasCode = StringUtils.hasText(value.getCode());
        boolean hasCodeVerifier = StringUtils.hasText(value.getCode_verifier());

        if (!hasCode) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("code is required for authorization_code grant")
                   .addPropertyNode("code")
                   .addConstraintViolation();
            return false;
        }

        if (!hasCodeVerifier) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("code_verifier is required for PKCE")
                   .addPropertyNode("code_verifier")
                   .addConstraintViolation();
            return false;
        }

        return true;
    }

    private boolean validatePreAuthorizedCodeGrant(OAuthTokenRequest value, ConstraintValidatorContext context) {
        // For pre-authorized_code grant, the pre_authorized_code field is required
        if (!StringUtils.hasText(value.getPre_authorized_code())) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("pre-authorized_code is required for pre-authorized_code grant")
                   .addPropertyNode("pre-authorized_code")
                   .addConstraintViolation();
            return false;
        }

        // tx_code is optional and validated by the service layer
        return true;
    }
}

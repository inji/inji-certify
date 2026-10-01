/*
 * Copyright 2024 Modular Open Source Identity Platform
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

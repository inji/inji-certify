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
package io.mosip.certify.core.dto;

import lombok.Data;
import jakarta.validation.constraints.NotBlank;
import io.mosip.certify.core.validation.ValidOAuthTokenRequest;

/**
 * OAuth 2.0 Token Request DTO
 * Used for exchanging authorization code for access token
 * 
 * Based on RFC 6749 and OpenID4VCI specification
 */
@Data
@ValidOAuthTokenRequest
public class OAuthTokenRequest {

    /**
     * REQUIRED. Value MUST be set to "authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code", or "refresh_token"
     */
    @NotBlank(message = "grant_type is required")
    private String grant_type;

    /**
     * REQUIRED (for authorization_code grant). The authorization code received from the authorization server.
     */
    private String code;


    /**
     * REQUIRED (for PKCE). Code verifier used in the Proof Key for Code Exchange (PKCE) extension.
     */
    private String code_verifier;

    /**
     * REQUIRED (for pre-authorized_code grant). The pre-authorized code received from the credential offer.
     */
    private String pre_authorized_code;

    /**
     * OPTIONAL (for pre-authorized_code grant). The transaction code if required by the credential offer.
     */
    private String tx_code;
}

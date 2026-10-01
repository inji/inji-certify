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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * OAuth 2.0 Token Response DTO
 * Returned when exchanging authorization code for access token
 * 
 * Based on RFC 6749 and OpenID4VCI specification
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OAuthTokenResponse {

    /**
     * REQUIRED. The access token issued by the authorization server.
     */
    @JsonProperty("access_token")
    private String accessToken;

    /**
     * REQUIRED. The type of the token issued. Value is case insensitive. Typically "Bearer".
     */
    @JsonProperty("token_type")
    private String tokenType;

    /**
     * RECOMMENDED. The lifetime in seconds of the access token.
     */
    @JsonProperty("expires_in")
    private Integer expiresIn;

    /**
     * OPTIONAL. The scope of the access token.
     */
    @JsonProperty("scope")
    private String scope;
}

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
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * OAuth 2.0 Authorization Server Metadata DTO as per RFC 8414
 * Note: authorization_endpoint is not included as this implementation
 * uses browser-less flows via interactive_authorization_endpoint.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class OAuthAuthorizationServerMetadataDTO {

    /**
     * The authorization server's issuer identifier
     */
    @JsonProperty("issuer")
    private String issuer;

    /**
     * URL of the authorization server's token endpoint
     */
    @JsonProperty("token_endpoint")
    private String tokenEndpoint;

    @JsonProperty("jwks_uri")
    private String jwksUri;

    /**
     * JSON array containing a list of the OAuth 2.0 grant type values that this authorization server supports
     */
    @JsonProperty("grant_types_supported")
    private List<String> grantTypesSupported;

    /**
     * JSON array containing a list of the OAuth 2.0 response type values that this authorization server supports
     */
    @JsonProperty("response_types_supported")
    private List<String> responseTypesSupported;

    /**
     * JSON array containing a list of PKCE code challenge methods supported by this authorization server
     */
    @JsonProperty("code_challenge_methods_supported")
    private List<String> codeChallengeMethodsSupported;

    /**
     * Interactive authorization endpoint for OAuth 2.0 flows
     */
    @JsonProperty("interactive_authorization_endpoint")
    private String interactiveAuthorizationEndpoint;

    /**
     * Indicates that Authorization Request for credential issuance must use
     * the Interactive Authorization Endpoint.
     */
    @JsonProperty("require_interactive_authorization_request")
    private Boolean requireInteractiveAuthorizationRequest;
}

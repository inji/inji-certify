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

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;

import java.util.List;

/**
 * Interactive Authorization Request (IAR) DTO for OpenID4VCI
 * Used for initial authorization requests (before VP presentation)
 */
@Data
@NoArgsConstructor
public class InteractiveAuthorizationRequest {

    /**
     * OAuth 2.0 Response Type - typically "code"
     */
    @NotBlank(message = "response_type is required")
    @JsonProperty("response_type")
    private String responseType;

    /**
     * OAuth 2.0 Client Identifier (optional for public clients)
     */
    @JsonProperty("client_id")
    private String clientId;

    /**
     * PKCE Code Challenge
     */
    @NotBlank(message = "code_challenge is required")
    @JsonProperty("code_challenge")
    private String codeChallenge;

    /**
     * PKCE Code Challenge Method - typically "S256"
     */
    @NotBlank(message = "code_challenge_method is required")
    @JsonProperty("code_challenge_method")
    private String codeChallengeMethod;

    /**
     * Supported interaction types - e.g., "urn:openid:dcp:iae:openid4vp_presentation"
     */
    @JsonProperty("interaction_types_supported")
    private String interactionTypesSupported;


    /**
     * Authorization details as per OpenID4VCI specification
     * Specifies the credential types being requested
     */
    @JsonProperty("authorization_details")
    private List<AuthorizationDetail> authorizationDetails;

}

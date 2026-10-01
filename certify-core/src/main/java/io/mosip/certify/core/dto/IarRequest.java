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

import io.mosip.certify.core.validation.ValidIar;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Interactive Authorization Request DTO for OpenID4VCI
 * Combines fields from both InteractiveAuthorizationRequest and IarAuthorizationRequest
 * Used for the unified /iae endpoint to handle both initial requests and VP presentation responses
 */
@Data
@NoArgsConstructor
@ValidIar
public class IarRequest {

    // Fields from InteractiveAuthorizationRequest (for initial authorization requests)
    
    /**
     * OAuth 2.0 Response Type - typically "code"
     */
    private String response_type;

    /**
     * OAuth 2.0 Client Identifier
     */
    private String client_id;

    /**
     * PKCE Code Challenge
     */
    private String code_challenge;

    /**
     * PKCE Code Challenge Method - typically "S256"
     */
    private String code_challenge_method;

    /**
     * Supported interaction types - e.g., "urn:openid:dcp:iae:openid4vp_presentation"
     */
    private String interaction_types_supported;

    /**
     * Authorization details as per OpenID4VCI specification
     * Specifies the credential types being requested
     */
    private List<AuthorizationDetail> authorization_details;

    // Fields from IarAuthorizationRequest (for VP presentation responses)
    
    /**
     * Authorization session identifier from initial IAR response
     */
    private String auth_session;

    /**
     * OpenID4VP presentation response (unencrypted or encrypted JWT)
     */
    private String openid4vp_response;

}

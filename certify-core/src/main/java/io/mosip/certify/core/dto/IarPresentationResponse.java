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
import io.mosip.certify.core.constants.IarStatus;
import io.mosip.certify.core.constants.InteractionType;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Interactive Authorization Response (IAR) DTO for OpenID4VCI
 * Response from POST /iae endpoint
 */
@Data
@NoArgsConstructor
public class IarPresentationResponse extends IarResponse{

    /**
     * Type of interaction required
     * - "urn:openid:dcp:iae:openid4vp_presentation": OpenID4VP presentation required
     */
    @JsonProperty("type")
    private InteractionType type;

    /**
     * Authorization session identifier for tracking the auth flow
     */
    @JsonProperty("auth_session")
    private String authSession;

    /**
     * OpenID4VP request details when interaction is required
     * Using Object to handle dynamic structure from Verify service
     */
    @JsonProperty("openid4vp_request")
    private Object openid4vpRequest;
}

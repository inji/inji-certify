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

/**
 * Interactive Authorization Request DTO for OpenID4VCI
 * Used for POST /iae endpoint to submit Verifiable Presentation response
 */
@Data
@NoArgsConstructor
public class IarAuthorizationRequest {

    /**
     * Authorization session identifier from initial IAR response
     */
    @NotBlank(message = "auth_session is required")
    @JsonProperty("auth_session")
    private String authSession;

    /**
     * OpenID4VP presentation response (unencrypted or encrypted JWT)
     */
    @NotBlank(message = "openid4vp_presentation is required")
    @JsonProperty("openid4vp_presentation")
    private String openid4vpPresentation;
}

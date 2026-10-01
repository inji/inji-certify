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
 * VP Verification Request DTO for VP Verifier service
 * Used for POST /vp-submission/direct-post endpoint
 */
@Data
@NoArgsConstructor
public class VpVerificationRequest {

    /**
     * The Verifiable Presentation token (required, not blank)
     */
    @NotBlank(message = "vp_token is required")
    @JsonProperty("vp_token")
    private String vpToken;

    /**
     * JSON string containing presentation submission details (required, not blank)
     */
    @NotBlank(message = "presentation_submission is required")
    @JsonProperty("presentation_submission")
    private String presentationSubmission;

    /**
     * The state parameter containing the request ID (required, not blank)
     */
    @NotBlank(message = "state is required")
    @JsonProperty("state")
    private String state;
}

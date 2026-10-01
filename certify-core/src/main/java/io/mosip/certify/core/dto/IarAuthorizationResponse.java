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
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Interactive Authorization Response DTO for OpenID4VCI
 * Response from POST /iae endpoint for Verifiable Presentation submission
 */
@Data
@NoArgsConstructor
public class IarAuthorizationResponse extends IarResponse{

    /**
     * OAuth 2.0 authorization code (if status is "ok")
     */
    @JsonProperty("code")
    private String code;

}
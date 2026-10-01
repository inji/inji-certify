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

/**
 * Response DTO from Verify Service VP Request endpoint
 * Contains the generated VP request details
 */
@Data
@NoArgsConstructor
public class VerifyVpResponse {

    @JsonProperty("transactionId")
    private String transactionId;

    @JsonProperty("requestId")
    private String requestId;

    @JsonProperty("authorizationDetails")
    private AuthorizationDetails authorizationDetails;

    @JsonProperty("expiresAt")
    private Long expiresAt;

    @Data
    @NoArgsConstructor
    public static class AuthorizationDetails {
        @JsonProperty("clientId")
        private String clientId;

        @JsonProperty("dcqlQuery")
        private Object dcqlQuery;

        @JsonProperty("nonce")
        private String nonce;

        @JsonProperty("responseUri")
        private String responseUri;

        @JsonProperty("responseType")
        private String responseType;

        @JsonProperty("responseMode")
        private String responseMode;

        @JsonProperty("issuedAt")
        private Long issuedAt;
    }
}

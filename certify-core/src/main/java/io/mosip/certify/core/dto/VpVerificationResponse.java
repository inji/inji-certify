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
 * VP Verification Response DTO from VP Verifier service
 * Response from POST /vp-submission/direct-post endpoint
 */
@Data
@NoArgsConstructor
public class VpVerificationResponse {

    /**
     * Verification status - typically "ok" for success or "error" for failure
     */
    @JsonProperty("status")
    private String status;

    /**
     * Error code if verification failed
     */
    @JsonProperty("error")
    private String error;

    /**
     * Error description if verification failed
     */
    @JsonProperty("error_description")
    private String errorDescription;

    /**
     * Request ID that was verified
     */
    @JsonProperty("request_id")
    private String requestId;

    /**
     * Transaction ID related to the verification
     */
    @JsonProperty("transaction_id")
    private String transactionId;

    /**
     * Additional verification details or claims extracted
     */
    @JsonProperty("verification_details")
    private Object verificationDetails;
}

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

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

import java.util.Map;

@Data
public class CredentialRequest {

    @NotBlank(message = ErrorConstants.INVALID_CREDENTIAL_REQUEST)
    @JsonProperty("credential_configuration_id")
    private String credentialConfigId;

    /**
     * REQUIRED (in this implementation).
     * JSON object containing proof(s) of possession of the key material the issued Credential shall be bound to.
     * Keys are proof types (e.g., "jwt"); values are non-empty lists of proof strings.
     */
    @Valid
    @NotEmpty(message = VCIErrorConstants.INVALID_PROOF)
    private Map<
            ProofType,
            @NotEmpty(message = VCIErrorConstants.INVALID_PROOF) List<
                    @NotBlank(message = VCIErrorConstants.INVALID_PROOF) String
                    >
            > proofs;
}
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

import io.mosip.certify.core.constants.VCIErrorConstants;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.Getter;

import java.util.List;

@Data
public class CredentialProof {

    @NotNull(message = VCIErrorConstants.INVALID_PROOF)
    private ProofType proofType;

    @NotEmpty(message = VCIErrorConstants.INVALID_PROOF)
    private List<@NotBlank(message = VCIErrorConstants.INVALID_PROOF) String> proofs;

    @Getter
    enum ProofType {
        JWT("jwt");

        private final String value;

        ProofType(String value) {
            this.value = value;
        }
    }
}
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
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
import jakarta.validation.constraints.NotNull;

import java.util.Map;

@Data
public class CredentialRequest {

    @NotBlank(message = ErrorConstants.INVALID_CREDENTIAL_CONFIG_ID)
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
            @NotBlank(message = ErrorConstants.UNSUPPORTED_PROOF_TYPE) String,
            @NotEmpty(message = VCIErrorConstants.INVALID_PROOF) List<
                    @NotBlank(message = VCIErrorConstants.INVALID_PROOF) String
                    >
            > proofs;
}

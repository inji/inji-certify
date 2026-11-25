package io.mosip.certify.core.dto;

import io.mosip.certify.core.constants.VCIErrorConstants;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

import java.util.Map;

/**
 * OpenID4VCI §8.2 / RFC 6749 §3.1: unknown parameters MUST be ignored. Needed per-DTO because
 * AppConfig's ObjectMapper fails on unknown properties globally; the admin APIs rely on that strictness.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CredentialRequest {

    /**
     * Required by this issuer (OpenID4VCI 1.0, 8.2): checked in the service together with credential_identifier.
     */
    @JsonProperty("credential_configuration_id")
    private String credentialConfigId;

    /**
     * Names a credential dataset from the token response's authorization_details (OpenID4VCI 1.0, 8.2).
     * This issuer never returns credential_identifiers, so any value it receives is unknown.
     */
    @JsonProperty("credential_identifier")
    private String credentialIdentifier;

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
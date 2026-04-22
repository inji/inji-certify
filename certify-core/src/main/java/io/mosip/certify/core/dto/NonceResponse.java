package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record NonceResponse(
        @JsonProperty("c_nonce")
        String cNonce
) {}

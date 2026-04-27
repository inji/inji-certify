package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum ProofType {
    JWT,
    LDP_VP;

    @JsonCreator
    public static ProofType fromValue(String value) {
        return ProofType.valueOf(value.toUpperCase());
    }
}

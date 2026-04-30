package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum ProofType {
    JWT;

    @JsonCreator
    public static ProofType fromValue(String value) {
        return ProofType.valueOf(value.toUpperCase());
    }
}

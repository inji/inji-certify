package io.mosip.certify.core.dto;

public record NonceTransaction(
        String cNonce,
        long cNonceIssuedEpoch,
        int cNonceExpireSeconds) {}

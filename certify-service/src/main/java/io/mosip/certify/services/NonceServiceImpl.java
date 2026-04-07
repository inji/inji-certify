package io.mosip.certify.services;

import io.mosip.certify.core.dto.NonceResponse;
import io.mosip.certify.core.dto.NonceTransaction;
import io.mosip.certify.core.spi.NonceService;
import io.mosip.certify.utils.AccessTokenJwtUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class NonceServiceImpl implements NonceService {

    private final AccessTokenJwtUtil accessTokenJwtUtil;

    private NonceCacheService nonceCacheService;

    @Value("${mosip.certify.cnonce-expire-seconds:300}")
    private int cNonceExpiresInSeconds;

    public NonceServiceImpl(AccessTokenJwtUtil accessTokenJwtUtil,
                            NonceCacheService nonceCacheService) {
        this.accessTokenJwtUtil = accessTokenJwtUtil;
        this.nonceCacheService = nonceCacheService;
    }

    @Override
    public NonceResponse generateNonce() {
        String cNonce = accessTokenJwtUtil.generateCNonce();
        NonceTransaction nonceTransaction = createNonceTransaction(cNonce);
        return new NonceResponse(cNonce);
    }

    private NonceTransaction createNonceTransaction(String cNonce) {
        Instant now = Instant.now();
        NonceTransaction nonceTransaction = new NonceTransaction(cNonce, now.getEpochSecond(), cNonceExpiresInSeconds);
                return nonceCacheService.setNonceTransaction(cNonce,nonceTransaction);
    }
}

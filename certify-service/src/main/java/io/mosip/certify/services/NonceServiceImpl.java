package io.mosip.certify.services;

import io.mosip.certify.core.dto.NonceResponse;
import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.NonceService;
import io.mosip.certify.utils.AccessTokenJwtUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
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
        VCIssuanceTransaction transaction = createNonceTransaction(cNonce);
        return new NonceResponse(cNonce);
    }

    private VCIssuanceTransaction createNonceTransaction(String cNonce) {
        try {
            Long cNonceIssuedTime = LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC);
            VCIssuanceTransaction transaction = new VCIssuanceTransaction();
            transaction.setCNonce(cNonce);
            transaction.setCNonceIssuedEpoch(cNonceIssuedTime);
            transaction.setCNonceExpireSeconds(cNonceExpiresInSeconds);
            return nonceCacheService.setNonceTransaction(cNonce, transaction);
        } catch (CertifyException e) {
            throw e;
        }
    }
}

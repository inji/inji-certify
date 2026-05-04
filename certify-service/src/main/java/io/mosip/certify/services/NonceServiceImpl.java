package io.mosip.certify.services;

import io.mosip.certify.core.dto.NonceResponse;
import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.core.spi.NonceService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class NonceServiceImpl implements NonceService {

    private VCICacheService vciCacheService;

    @Value("${mosip.certify.cnonce-expire-seconds:300}")
    private int cNonceExpiresInSeconds;

    public NonceServiceImpl(VCICacheService vciCacheService) {
        this.vciCacheService = vciCacheService;
    }

    @Override
    public NonceResponse generateNonce() {
        String cNonce = generateCNonce();
        createNonceTransaction(cNonce);
        return new NonceResponse(cNonce);
    }

    public String generateCNonce() {
        return java.util.UUID.randomUUID().toString();
    }

    private void createNonceTransaction(String cNonce) {
        long cNonceIssuedTime = LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC);
        VCIssuanceTransaction transaction = new VCIssuanceTransaction();
        transaction.setCNonce(cNonce);
        transaction.setCNonceIssuedEpoch(cNonceIssuedTime);
        transaction.setCNonceExpireSeconds(cNonceExpiresInSeconds);
        vciCacheService.setNonceTransaction(cNonce, transaction);
    }
}

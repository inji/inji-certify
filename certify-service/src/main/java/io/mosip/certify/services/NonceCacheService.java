package io.mosip.certify.services;

import io.mosip.certify.core.constants.NonceErrorConstants;
import io.mosip.certify.core.dto.NonceTransaction;
import io.mosip.certify.core.exception.CertifyException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CachePut;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class NonceCacheService {

    @Autowired
    private CacheManager cacheManager;

    @Value("${spring.cache.type:simple}")
    private String cacheType;

    private static final String NONCE_CACHE = "nonce";
    
    @PostConstruct
    public void validateCacheConfiguration() {
        log.info("Cache type configured: {}", cacheType);

        if ("simple".equalsIgnoreCase(cacheType)) {
            log.warn("CRITICAL WARNING: Simple cache configured for production deployment " +
                    "'simple' cache uses in-memory storage isolated to each pod, " +
                    "Multi-pod deployments will experience cache inconsistencies and MAY BREAK FUNCTIONALLY, " +
                    "Current configuration: spring.cache.type=simple (in-memory, non-distributed), " +
                    "Switch to Redis cache for multi-pod deployments, Set spring.cache.type=redis in your configuration ");
        } else if ("redis".equalsIgnoreCase(cacheType)) {
            log.info("Redis cache is configured - suitable for multi-pod deployment");
        } else {
            log.warn("Unknown cache type configured: {}. Please verify configuration.", cacheType);
        }
    }

    @CachePut(value = NONCE_CACHE, key = "'txn:' + #cNonce")
    public NonceTransaction setNonceTransaction(String cNonce,  NonceTransaction nonceTransaction) {
        return nonceTransaction;
    }

    public NonceTransaction getNonceTransaction(String cNonce) {
        Cache cache = cacheManager.getCache(NONCE_CACHE);
        if (cache == null) {
            log.error("Cache {} not available. Please verify cache configuration.", NONCE_CACHE);
            throw new CertifyException(NonceErrorConstants.CACHE_NOT_AVAILABLE,
                    "Nonce cache is not configured. Please verify cache configuration.");
        }
        return cache.get("txn:" + cNonce, NonceTransaction.class);
    }
    
}

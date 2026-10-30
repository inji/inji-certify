package io.mosip.certify;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialOfferResponse;
import io.mosip.certify.core.dto.OAuthAuthorizationServerMetadataDTO;
import io.mosip.certify.core.dto.PreAuthCodeData;
import io.mosip.certify.core.dto.PreAuthTransaction;
import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.services.VCICacheService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.data.redis.cache.RedisCache;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class VCICacheServiceTest {
    @Mock
    private CacheManager cacheManager;

    @Mock
    private Cache cache;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private VCICacheService vciCacheService;

    private static final String TEST_ACCESS_TOKEN_HASH = "testHash123";
    private static final String VCISSUANCE_CACHE = "vcissuance";
    private static final String PRE_AUTH_CODE_CACHE = "preAuthCodeCache";
    private static final String CREDENTIAL_OFFER_CACHE = "credentialOfferCache";

    @Before
    public void setup() {
        when(cacheManager.getCache(anyString())).thenReturn(cache);
    }

    @Test
    public void setVCITransaction_ShouldReturnSameTransaction() {

        VCIssuanceTransaction transaction = new VCIssuanceTransaction();
        transaction.setCNonce("test-cnonce");
        VCIssuanceTransaction result = vciCacheService.setVCITransaction(TEST_ACCESS_TOKEN_HASH, transaction);
        assertNotNull(result);
        assertEquals(transaction, result);
    }

    @Test
    public void getVCITransaction_WhenTransactionExists_ShouldReturnTransaction() {
        when(cacheManager.getCache(VCISSUANCE_CACHE)).thenReturn(cache);
        VCIssuanceTransaction transaction = new VCIssuanceTransaction();
        transaction.setCNonce("test-cnonce");
        when(cache.get(TEST_ACCESS_TOKEN_HASH, VCIssuanceTransaction.class)).thenReturn(transaction);
        VCIssuanceTransaction result = vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH);
        assertEquals(transaction, result);
        verify(cacheManager).getCache(VCISSUANCE_CACHE);
        verify(cache).get(eq(TEST_ACCESS_TOKEN_HASH), eq(VCIssuanceTransaction.class));
    }

    @Test
    public void setPreAuthCodeData_Success() {
        String code = "test-code";
        PreAuthCodeData data = new PreAuthCodeData();
        vciCacheService.setPreAuthCodeData(code, data);
        verify(cacheManager).getCache(PRE_AUTH_CODE_CACHE);
        verify(cache).put(eq(Constants.PRE_AUTH_CODE_PREFIX + code), eq(data));
    }

    @Test
    public void getPreAuthCodeData_Success() {
        String code = "test-code";
        PreAuthCodeData data = new PreAuthCodeData();
        Cache.ValueWrapper wrapper = mock(Cache.ValueWrapper.class);
        when(wrapper.get()).thenReturn(data);
        when(cache.get(Constants.PRE_AUTH_CODE_PREFIX + code)).thenReturn(wrapper);

        PreAuthCodeData result = vciCacheService.getPreAuthCodeData(code);
        assertEquals(data, result);
    }

    @Test
    public void setCredentialOffer_Success() {
        String offerId = "test-offer-id";
        CredentialOfferResponse offer = new CredentialOfferResponse();
        vciCacheService.setCredentialOffer(offerId, offer);
        verify(cacheManager).getCache(CREDENTIAL_OFFER_CACHE);
        verify(cache).put(eq(Constants.CREDENTIAL_OFFER_PREFIX + offerId), eq(offer));
    }

    @Test
    public void getCredentialOffer_Success() {
        String offerId = "test-offer-id";
        CredentialOfferResponse offer = new CredentialOfferResponse();
        Cache.ValueWrapper wrapper = mock(Cache.ValueWrapper.class);
        when(wrapper.get()).thenReturn(offer);
        when(cache.get(Constants.CREDENTIAL_OFFER_PREFIX + offerId)).thenReturn(wrapper);

        CredentialOfferResponse result = vciCacheService.getCredentialOffer(offerId);
        assertEquals(offer, result);
    }

    @Test
    public void validateCacheConfiguration_Simple() {
        ReflectionTestUtils.setField(vciCacheService, "cacheType", "simple");
        vciCacheService.validateCacheConfiguration();
        // Just verifying no exception
    }

    @Test
    public void validateCacheConfiguration_Redis() {
        ReflectionTestUtils.setField(vciCacheService, "cacheType", "redis");
        vciCacheService.validateCacheConfiguration();
    }

    @Test
    public void validateCacheConfiguration_Unknown() {
        ReflectionTestUtils.setField(vciCacheService, "cacheType", "unknown");
        vciCacheService.validateCacheConfiguration();
    }

    @Test
    public void setCredentialOffer_RedisCache() {
        RedisCache redisCache = mock(RedisCache.class);
        when(cacheManager.getCache(CREDENTIAL_OFFER_CACHE)).thenReturn(redisCache);

        String offerId = "test-offer-id";
        CredentialOfferResponse offer = new CredentialOfferResponse();
        vciCacheService.setCredentialOffer(offerId, offer);

        verify(redisCache).put(eq(Constants.CREDENTIAL_OFFER_PREFIX + offerId), eq(offer));
    }

    // Tests for cache null handling

    @Test
    public void getVCITransaction_WhenCacheIsNull_ReturnsNull() {
        when(cacheManager.getCache(VCISSUANCE_CACHE)).thenReturn(null);

        VCIssuanceTransaction result = vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH);

        assertEquals(null, result);
        verify(cacheManager).getCache(VCISSUANCE_CACHE);
    }

    @Test(expected = IllegalStateException.class)
    public void getCredentialOffer_WhenCacheIsNull_ThrowsIllegalStateException() {
        when(cacheManager.getCache(CREDENTIAL_OFFER_CACHE)).thenReturn(null);

        vciCacheService.getCredentialOffer("test-offer-id");
    }

    @Test(expected = IllegalStateException.class)
    public void setCredentialOffer_WhenCacheIsNull_ThrowsIllegalStateException() {
        when(cacheManager.getCache(CREDENTIAL_OFFER_CACHE)).thenReturn(null);

        vciCacheService.setCredentialOffer("test-offer-id", new CredentialOfferResponse());
    }

    @Test
    public void getCredentialOffer_WhenNotFound_ReturnsNull() {
        String offerId = "test-offer-id";
        when(cacheManager.getCache(CREDENTIAL_OFFER_CACHE)).thenReturn(cache);
        when(cache.get(Constants.CREDENTIAL_OFFER_PREFIX + offerId)).thenReturn(null);

        CredentialOfferResponse result = vciCacheService.getCredentialOffer(offerId);

        assertEquals(null, result);
    }

    // Tests for setTransaction

    @Test
    public void setPreAuthTransaction_ShouldReturnSameTransaction_PreAuth() {
        String accessToken = "test-access-token";
        PreAuthTransaction transaction = new PreAuthTransaction();
        transaction.setCredentialConfigurationId("test-config");
        transaction.setClaims(java.util.Collections.emptyMap());

        PreAuthTransaction result = vciCacheService.setPreAuthTransaction(accessToken, transaction);

        assertNotNull(result);
        assertEquals(transaction, result);
    }

    // Tests for setASMetadata and getASMetadata

    private static final String AS_METADATA_CACHE = "asMetadataCache";

    @Test
    public void should_returnTransaction_when_preAuthTransactionExists() {
        PreAuthTransaction tx = new PreAuthTransaction();
        when(cache.get("h", PreAuthTransaction.class)).thenReturn(tx);
        assertEquals(tx, vciCacheService.getPreAuthTransaction("h"));
    }

    @Test
    public void should_returnNull_when_preAuthCacheIsNull() {
        when(cacheManager.getCache("preAuthCacheTxn")).thenReturn(null);
        assertNull(vciCacheService.getPreAuthTransaction("h"));
    }

    @Test
    public void should_returnSameTransaction_when_preAuthTransactionSet() {
        PreAuthTransaction tx = new PreAuthTransaction();
        assertEquals(tx, vciCacheService.setPreAuthTransaction("h", tx));
    }

    @Test
    public void should_returnSameTransaction_when_nonceTransactionSet() {
        VCIssuanceTransaction tx = new VCIssuanceTransaction();
        assertEquals(tx, vciCacheService.setNonceTransaction("nonce", tx));
    }

    @Test
    public void should_returnTransaction_when_nonceTransactionExists() {
        VCIssuanceTransaction tx = new VCIssuanceTransaction();
        when(cache.get("txn:nonce", VCIssuanceTransaction.class)).thenReturn(tx);
        assertEquals(tx, vciCacheService.getNonceTransaction("nonce"));
    }

    @Test
    public void should_throwCertifyException_when_nonceCacheIsNull() {
        when(cacheManager.getCache("nonce")).thenReturn(null);
        assertThrows(CertifyException.class, () -> vciCacheService.getNonceTransaction("nonce"));
    }

    @Test
    public void should_returnFalse_when_preAuthCodeDataMissing() {
        when(cache.get("pre_auth_code:code")).thenReturn(null);
        assertFalse(vciCacheService.claimPreAuthCode("code"));
        verify(cache, never()).putIfAbsent(anyString(), any());
    }

    @Test
    public void should_markAndReturnTrue_when_preAuthCodeIsValidAndUnused() {
        PreAuthCodeData data = new PreAuthCodeData();
        Cache.ValueWrapper dataWrapper = mock(Cache.ValueWrapper.class);
        when(dataWrapper.get()).thenReturn(data);
        when(cache.get("pre_auth_code:code")).thenReturn(dataWrapper);
        when(cache.putIfAbsent("used:code", true)).thenReturn(null);

        assertTrue(vciCacheService.claimPreAuthCode("code"));
        verify(cache).putIfAbsent("used:code", true);
        verify(cache).evict("pre_auth_code:code");
    }

    @Test
    public void should_returnFalse_when_preAuthCodeAlreadyUsed() {
        PreAuthCodeData data = new PreAuthCodeData();
        Cache.ValueWrapper dataWrapper = mock(Cache.ValueWrapper.class);
        when(dataWrapper.get()).thenReturn(data);
        when(cache.get("pre_auth_code:code")).thenReturn(dataWrapper);
        Cache.ValueWrapper existing = mock(Cache.ValueWrapper.class);
        when(cache.putIfAbsent("used:code", true)).thenReturn(existing);

        assertFalse(vciCacheService.claimPreAuthCode("code"));
        verify(cache, never()).evict(anyString());
    }

    @Test
    public void should_throwServerError_when_preAuthCodeCacheIsNullOnClaim() {
        when(cacheManager.getCache("preAuthCodeCache")).thenReturn(null);
        CertifyException ex = assertThrows(CertifyException.class,
                () -> vciCacheService.claimPreAuthCode("code"));
        assertEquals(ErrorConstants.SERVER_ERROR, ex.getErrorCode());
    }

    @Test
    public void should_returnTrueThenFalse_when_cacheAllowsOnlyOneClaim() {
        PreAuthCodeData data = new PreAuthCodeData();
        Cache.ValueWrapper dataWrapper = mock(Cache.ValueWrapper.class);
        when(dataWrapper.get()).thenReturn(data);
        when(cache.get("pre_auth_code:code")).thenReturn(dataWrapper);
        Cache.ValueWrapper existing = mock(Cache.ValueWrapper.class);
        when(cache.putIfAbsent("used:code", true)).thenReturn(null).thenReturn(existing);

        assertTrue(vciCacheService.claimPreAuthCode("code"));
        assertFalse(vciCacheService.claimPreAuthCode("code"));
    }

    @Test
    public void should_letExactlyOneWin_when_twoInstancesClaimConcurrentlyOverSharedCache() throws Exception {
        ConcurrentMapCacheManager backing = new ConcurrentMapCacheManager("preAuthCodeCache");
        Cache realCache = backing.getCache("preAuthCodeCache");
        realCache.put(Constants.PRE_AUTH_CODE_PREFIX + "code", new PreAuthCodeData());

        CyclicBarrier bothRead = new CyclicBarrier(2);
        Cache barrierCache = new BarrierOnReadCache(realCache, Constants.PRE_AUTH_CODE_PREFIX + "code", bothRead);
        CacheManager sharedManager = new SingleCacheManager(barrierCache);

        VCICacheService first = new VCICacheService(sharedManager);
        VCICacheService second = new VCICacheService(sharedManager);

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger winners = new AtomicInteger();
            Future<Boolean> f1 = pool.submit(() -> { start.await(); return first.claimPreAuthCode("code"); });
            Future<Boolean> f2 = pool.submit(() -> { start.await(); return second.claimPreAuthCode("code"); });

            start.countDown();

            if (Boolean.TRUE.equals(f1.get(5, TimeUnit.SECONDS))) winners.incrementAndGet();
            if (Boolean.TRUE.equals(f2.get(5, TimeUnit.SECONDS))) winners.incrementAndGet();

            assertEquals("Exactly one instance must redeem the pre-authorized code", 1, winners.get());
        } finally {
            pool.shutdownNow();
        }
    }

    /** CacheManager that always hands back a single supplied cache - used to share one cache. */
    private static final class SingleCacheManager implements CacheManager {
        private final Cache cache;
        SingleCacheManager(Cache cache) { this.cache = cache; }
        @Override public Cache getCache(String name) { return cache; }
        @Override public java.util.Collection<String> getCacheNames() { return java.util.List.of(cache.getName()); }
    }

    /**
     * Delegating cache that makes {@code get(barrierKey)} block on a 2-party barrier until both
     * threads have read the key. Forces both claimers through the read phase before either marks,
     * deterministically exposing a check-then-mark race. All other operations pass straight through.
     */
    private static final class BarrierOnReadCache implements Cache {
        private final Cache delegate;
        private final String barrierKey;
        private final CyclicBarrier barrier;
        BarrierOnReadCache(Cache delegate, String barrierKey, CyclicBarrier barrier) {
            this.delegate = delegate; this.barrierKey = barrierKey; this.barrier = barrier;
        }
        @Override public String getName() { return delegate.getName(); }
        @Override public Object getNativeCache() { return delegate.getNativeCache(); }
        @Override public ValueWrapper get(Object key) {
            ValueWrapper value = delegate.get(key);
            if (barrierKey.equals(key)) {
                try {
                    barrier.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(e);
                } catch (BrokenBarrierException | TimeoutException e) {
                    throw new IllegalStateException(e);
                }
            }
            return value;
        }
        @Override public <T> T get(Object key, Class<T> type) { return delegate.get(key, type); }
        @Override public <T> T get(Object key, java.util.concurrent.Callable<T> valueLoader) { return delegate.get(key, valueLoader); }
        @Override public void put(Object key, Object value) { delegate.put(key, value); }
        @Override public ValueWrapper putIfAbsent(Object key, Object value) { return delegate.putIfAbsent(key, value); }
        @Override public void evict(Object key) { delegate.evict(key); }
        @Override public void clear() { delegate.clear(); }
    }
}


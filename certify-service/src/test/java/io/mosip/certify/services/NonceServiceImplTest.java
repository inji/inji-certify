package io.mosip.certify.services;

import io.mosip.certify.core.dto.NonceResponse;
import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.core.exception.CertifyException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import java.lang.reflect.Field;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class NonceServiceImplTest {

    @Mock
    private NonceCacheService nonceCacheService;

    private NonceServiceImpl nonceService;

    @Before
    public void setup() throws Exception {

        nonceService = new NonceServiceImpl(nonceCacheService);
        // Inject @Value field manually
        Field field = NonceServiceImpl.class.getDeclaredField("cNonceExpiresInSeconds");
        field.setAccessible(true);
        field.set(nonceService, 300);
    }

    @Test
    public void testGenerateNonce_success() {
        NonceResponse response = nonceService.generateNonce();

        assertNotNull(response);
        assertNotNull(response.cNonce());

        verify(nonceCacheService, times(1))
                .setNonceTransaction(eq(response.cNonce()), any(VCIssuanceTransaction.class));
    }


    @Test
    public void testGenerateNonce_whenCacheFails_shouldThrowException() {
        when(nonceCacheService.setNonceTransaction(anyString(), any(VCIssuanceTransaction.class)))
                .thenThrow(new CertifyException("CACHE_ERROR", "Cache failure"));

        CertifyException ex = assertThrows(CertifyException.class, () -> {
            nonceService.generateNonce();
        });

        assertEquals("CACHE_ERROR", ex.getErrorCode());
        assertEquals("Cache failure", ex.getMessage());
    }
}
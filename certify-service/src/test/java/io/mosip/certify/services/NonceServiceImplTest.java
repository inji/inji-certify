package io.mosip.certify.services;

import io.mosip.certify.core.dto.NonceResponse;
import io.mosip.certify.core.dto.NonceTransaction;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.utils.AccessTokenJwtUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.lang.reflect.Field;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class NonceServiceImplTest {

    @Mock
    private AccessTokenJwtUtil accessTokenJwtUtil;

    @Mock
    private NonceCacheService nonceCacheService;

    @InjectMocks
    private NonceServiceImpl nonceService;

    @Before
    public void setup() throws Exception {
        // Inject @Value field manually
        Field field = NonceServiceImpl.class.getDeclaredField("cNonceExpiresInSeconds");
        field.setAccessible(true);
        field.set(nonceService, 300);
    }

    @Test
    public void testGenerateNonce_success() {

        String mockNonce = "test-cnonce-123";

        when(accessTokenJwtUtil.generateCNonce()).thenReturn(mockNonce);


        when(nonceCacheService.setNonceTransaction(anyString(), any(NonceTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(1));


        NonceResponse response = nonceService.generateNonce();


        assertNotNull(response);
        assertEquals(mockNonce, response.cNonce());

        verify(accessTokenJwtUtil, times(1)).generateCNonce();
        verify(nonceCacheService, times(1))
                .setNonceTransaction(eq(mockNonce), any(NonceTransaction.class));
    }


    @Test(expected = CertifyException.class)
    public void testGenerateNonce_whenCacheFails_shouldThrowException() {

        String mockNonce = "test-nonce-123";

        when(accessTokenJwtUtil.generateCNonce()).thenReturn(mockNonce);
        when(nonceCacheService.setNonceTransaction(anyString(), any(NonceTransaction.class)))
                .thenThrow(new CertifyException("CACHE_ERROR", "Cache failure"));

        nonceService.generateNonce();
    }
}
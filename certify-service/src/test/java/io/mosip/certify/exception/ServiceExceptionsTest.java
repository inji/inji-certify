package io.mosip.certify.exception;

import org.junit.Test;

import static org.junit.Assert.*;

public class ServiceExceptionsTest {

    @Test
    public void should_retainErrorCodeAndMessage_when_statusListExceptionIsCreated() {
        StatusListException ex = new StatusListException("ERR_CODE", "something failed");
        assertEquals("ERR_CODE", ex.getErrorCode());
        assertEquals("something failed", ex.getMessage());
        assertTrue(ex instanceof Exception);
    }

    @Test
    public void should_retainMessage_when_revocationExceptionIsCreated() {
        RevocationException ex = new RevocationException("cannot revoke");
        assertEquals("cannot revoke", ex.getMessage());
        assertTrue(ex instanceof RuntimeException);
    }
}

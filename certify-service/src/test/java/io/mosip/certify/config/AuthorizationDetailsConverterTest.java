package io.mosip.certify.config;

import io.mosip.certify.core.dto.AuthorizationDetail;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class AuthorizationDetailsConverterTest {

    private final AuthorizationDetailsConverter converter = new AuthorizationDetailsConverter();

    @Test
    public void should_returnNull_when_inputIsNull() {
        assertNull(converter.convert(null));
    }

    @Test
    public void should_returnNull_when_inputIsEmpty() {
        assertNull(converter.convert("   "));
    }

    @Test
    public void should_returnList_when_jsonIsValid() {
        String json = "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"MockVC\"}]";
        List<AuthorizationDetail> result = converter.convert(json);
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("openid_credential", result.get(0).getType());
    }

    @Test
    public void should_returnEmptyList_when_jsonIsEmptyArray() {
        List<AuthorizationDetail> result = converter.convert("[]");
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    public void should_throwIllegalArgument_when_jsonIsInvalid() {
        assertThrows(IllegalArgumentException.class, () -> converter.convert("not-json"));
    }
}

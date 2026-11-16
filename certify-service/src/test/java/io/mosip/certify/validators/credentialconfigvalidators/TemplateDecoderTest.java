package io.mosip.certify.validators.credentialconfigvalidators;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class TemplateDecoderTest {

    private static final String TEMPLATE = "{\"family_name\": \"${familyName}\"}";

    @Test
    public void should_decodeTheTemplate_when_itIsBase64() {
        String stored = Base64.getEncoder().encodeToString(TEMPLATE.getBytes(StandardCharsets.UTF_8));

        assertEquals(TEMPLATE, TemplateDecoder.decodeVcTemplate(stored));
        assertEquals(TEMPLATE, TemplateDecoder.decodeVcTemplate(" " + stored + "\n"));
    }

    @Test
    public void should_returnTheInput_when_itIsRawJson() {
        assertEquals(TEMPLATE, TemplateDecoder.decodeVcTemplate(TEMPLATE));
    }

    @Test
    public void should_returnTheInput_when_itIsNullOrEmpty() {
        assertNull(TemplateDecoder.decodeVcTemplate(null));
        assertEquals("", TemplateDecoder.decodeVcTemplate(""));
    }
}

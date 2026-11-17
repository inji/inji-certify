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
    public void should_decodeTheTemplate_when_itsBase64IsWrappedAcrossLines() {
        String template = "{\"family_name\": \"${familyName}\", \"given_name\": \"${givenName}\", \"birth_date\": \"${birthDate}\"}";
        // the MIME encoder wraps at 76 characters with CRLF
        String crlfWrapped = Base64.getMimeEncoder().encodeToString(template.getBytes(StandardCharsets.UTF_8));
        String lfWrapped = crlfWrapped.replace("\r\n", "\n");

        assertTrue(crlfWrapped.contains("\r\n"));
        assertEquals(template, TemplateDecoder.decodeVcTemplate(crlfWrapped));
        assertEquals(template, TemplateDecoder.decodeVcTemplate(lfWrapped));
    }

    @Test
    public void should_returnTheInput_when_itIsRawJsonWrappedAcrossLines() {
        String rawJson = "{\n  \"family_name\": \"${familyName}\"\r\n}";

        assertEquals(rawJson, TemplateDecoder.decodeVcTemplate(rawJson));
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

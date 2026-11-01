package io.mosip.certify.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.dto.CredentialRequest;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AppConfigTest {

    @Test
    public void credentialRequestWithUnknownFieldStillDeserializes() throws Exception {
        ObjectMapper mapper = new AppConfig().objectMapper();
        String json = "{\"format\":\"ldp_vc\",\"unknown_future_parameter\":\"ignored\"}";
        CredentialRequest request = mapper.readValue(json, CredentialRequest.class);
        assertEquals("ldp_vc", request.getFormat());
    }
}

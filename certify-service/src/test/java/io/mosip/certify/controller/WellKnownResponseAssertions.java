package io.mosip.certify.controller;

import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Shared checks for the .well-known endpoints (#1143). Certify does not sign its metadata, so every
 * Accept value gets the unsigned JSON document. OID4VCI 1.0 section 12.2.2 requires a Content-Type
 * "in all cases", whatever the Wallet sends in Accept.
 */
final class WellKnownResponseAssertions {

    static final String ACCEPT_VALUES = "io.mosip.certify.controller.WellKnownResponseAssertions#acceptValues";

    private WellKnownResponseAssertions() {
    }

    static List<String> acceptValues() {
        return List.of("application/jwt", "application/xml", "text/html", "text/plain", "*/*");
    }

    static void assertServesJsonDocument(MockMvc mockMvc, String path, String accept) throws Exception {
        String json = mockMvc.perform(get(path).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        mockMvc.perform(get(path).accept(accept))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(content().json(json, true));
    }
}

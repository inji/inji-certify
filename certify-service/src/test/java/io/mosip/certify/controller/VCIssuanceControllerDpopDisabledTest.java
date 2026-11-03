package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.core.constants.AuthErrorMessages;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.dto.ProofType;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.services.VCICacheService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The real filter, resolver and advice together, on a deployment with DPoP disabled.
 *
 * <p>A class of its own because {@link VCIssuanceControllerTest} mocks a
 * {@code DpopProofValidator} bean, and its presence is what keeps DPoP enabled. Without
 * it, the filter and the advice see the absent bean exactly as a Bearer-only deployment does.
 */
@RunWith(SpringRunner.class)
@WebMvcTest(value = VCIssuanceController.class)
@TestPropertySource(properties = "mosip.certify.dpop.enabled=false")
public class VCIssuanceControllerDpopDisabledTest {

    // The filter runs only for the URIs in mosip.certify.authn.filter-urls, which carry the
    // servlet path. A request to /issuance/credential alone would skip it.
    private static final String CREDENTIAL_URI = "/v1/certify/issuance/credential";

    ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    MockMvc mockMvc;

    @MockBean
    AuditPlugin auditWrapper;

    @MockBean
    ParsedAccessToken parsedAccessToken;

    @MockBean
    VCIssuanceService vcIssuanceService;

    @MockBean
    VCICacheService vciCacheService;

    @Test
    public void should_answer401WithBearerChallenge_when_dpopIsDisabledAndDpopSchemeIsUsed() throws Exception {
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setCredentialConfigId("TestId");
        credentialRequest.setProofs(Map.of(ProofType.JWT, List.of("dummy_jwt_proof")));

        mockMvc.perform(post(CREDENTIAL_URI)
                        .servletPath("/v1/certify")
                        .header(HttpHeaders.AUTHORIZATION, "DPoP header.payload.signature")
                        .header("DPoP", "a.proof.jwt")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value(ErrorConstants.INVALID_AUTH_TOKEN))
                .andExpect(jsonPath("$.error_description").value(AuthErrorMessages.ERROR_DPOP_NOT_SUPPORTED))
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
                        "Bearer error=\"invalid_token\", error_description=\"" + AuthErrorMessages.ERROR_DPOP_NOT_SUPPORTED + "\""));

        // Refused at the filter: the controller never ran.
        verifyNoInteractions(vcIssuanceService);
    }
}

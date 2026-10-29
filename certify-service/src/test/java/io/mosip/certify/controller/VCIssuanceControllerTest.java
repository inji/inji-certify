package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.config.AppConfig;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.services.VCICacheService;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The controller on its own, with AccessTokenValidationFilter bypassed on purpose.
 *
 * <p>These tests post to {@code /issuance/credential} without the {@code /v1/certify} servlet
 * path, so the request URI does not match {@code mosip.certify.authn.filter-urls} and the filter
 * does not run. Authentication state comes from the mocked {@link ParsedAccessToken} instead.
 * The filter path is covered by {@link VCIssuanceControllerDpopDisabledTest}.
 */
@RunWith(SpringRunner.class)
@WebMvcTest(value = VCIssuanceController.class)
@Import(VCIssuanceControllerTest.ApplicationObjectMapper.class)
public class VCIssuanceControllerTest {

    /**
     * Binds requests with the application's own ObjectMapper, as the running service does, rather
     * than the web slice's default one, so the test reflects production behaviour for unknown fields.
     */
    @TestConfiguration
    static class ApplicationObjectMapper {
        @Bean
        ObjectMapper objectMapper() {
            return new AppConfig(Mockito.mock(KeymanagerService.class)).objectMapper();
        }
    }

    ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    MockMvc mockMvc;

    @MockBean
    AuditPlugin auditWrapper;


    @MockBean
    ParsedAccessToken parsedAccessToken;

    // Its presence is what keeps DPoP enabled for this class, as on a default deployment.
    // VCIssuanceControllerDpopDisabledTest leaves it out to test the disabled mode.
    @MockBean
    io.mosip.certify.dpop.DpopProofValidator dpopProofValidator;

    @MockBean
    VCIssuanceService vcIssuanceService;

    @MockBean
    VCICacheService vciCacheService;

    @Test
    public void getVerifiableCredential_withValidDetails_thenPass() throws Exception {
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setProofs(Map.of(ProofType.JWT,List.of("dummy_jwt_proof")));
        credentialRequest.setCredentialConfigId("TestId");

        CredentialResponse credentialResponse = new CredentialResponse<JsonLDObject>();
        CredentialResponse.CredentialWrapper credentialWrapper = new CredentialResponse.CredentialWrapper<JsonLDObject>();
        credentialWrapper.setCredential(new JsonLDObject());
        credentialResponse.setCredentials(List.of(credentialWrapper));
        Mockito.when(vcIssuanceService.getCredential(credentialRequest)).thenReturn(credentialResponse);

        mockMvc.perform(post("/issuance/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentials").exists());
    }

    @Test
    public void getVerifiableCredential_withInvalid_CredentialConfigId_thenFail() throws Exception {
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setCredentialConfigId(null);
        credentialRequest.setProofs(Map.of(ProofType.JWT,List.of("dummy_jwt_proof")));

        mockMvc.perform(post("/issuance/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(ErrorConstants.INVALID_CREDENTIAL_REQUEST));

        credentialRequest.setCredentialConfigId("  ");
        mockMvc.perform(post("/issuance/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(ErrorConstants.INVALID_CREDENTIAL_REQUEST));
    }

    @Test
    public void getVerifiableCredential_withInvalidProof_thenFail() throws Exception {
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setCredentialConfigId("TestId");

        credentialRequest.setProofs(null);
        mockMvc.perform(post("/issuance/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(VCIErrorConstants.INVALID_PROOF));

        credentialRequest.setProofs(Map.of());

        CertifyException certifyException = new CertifyException(ErrorConstants.UNSUPPORTED_PROOF_TYPE,"The proof type is not supported.");
        Mockito.when(vcIssuanceService.getCredential(credentialRequest)).thenThrow(certifyException);
        mockMvc.perform(post("/issuance/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(VCIErrorConstants.INVALID_PROOF));
    }

    @Test
    public void getVerifiableCredential_withInvalidNonceException_thenFail() throws Exception {
        CredentialDefinition credentialDefinition = new CredentialDefinition();
        credentialDefinition.setType(Arrays.asList("VerifiableCredential", "SampleVerifiableCredential_ldp"));
        credentialDefinition.setContext(Arrays.asList("https://www.w3.org/2018/credentials/v1"));
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setCredentialConfigId("TestId");
        credentialRequest.setProofs(Map.of(ProofType.JWT,List.of("dummy_jwt_proof")));

        CertifyException exception = new CertifyException("invalid_nonce", "c_nonce is invalid or expired");
        Mockito.when(vcIssuanceService.getCredential(credentialRequest)).thenThrow(exception);

        mockMvc.perform(post("/issuance/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(exception.getErrorCode()))
                .andExpect(jsonPath("$.error_description").value(exception.getMessage()));
    }

    @Test
    public void should_ignoreUnknownField_when_requestIsValid() throws Exception {
        CredentialResponse credentialResponse = new CredentialResponse<JsonLDObject>();
        CredentialResponse.CredentialWrapper credentialWrapper = new CredentialResponse.CredentialWrapper<JsonLDObject>();
        credentialWrapper.setCredential(new JsonLDObject());
        credentialResponse.setCredentials(List.of(credentialWrapper));
        Mockito.when(vcIssuanceService.getCredential(Mockito.any())).thenReturn(credentialResponse);

        // OpenID4VCI §8.2: an unrecognised request parameter must be ignored, not rejected.
        String bodyWithUnknownField = "{\"credential_configuration_id\":\"TestId\"," +
                "\"proofs\":{\"jwt\":[\"dummy_jwt_proof\"]}," +
                "\"some_unknown_param\":\"x\"}";

        mockMvc.perform(post("/issuance/credential")
                        .content(bodyWithUnknownField)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentials").exists());
    }

    @Test
    public void should_returnInvalidRequest_when_credentialRequestJsonIsMalformed() throws Exception {
        mockMvc.perform(post("/issuance/credential")
                        .content("{invalid-json}")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("Malformed JSON syntax error"));
    }
}
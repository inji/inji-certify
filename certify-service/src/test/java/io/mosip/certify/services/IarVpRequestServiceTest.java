package io.mosip.certify.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.services.VerifiablePresentationRequestService;
import io.mosip.certify.core.dto.InteractiveAuthorizationRequest;
import io.mosip.certify.core.dto.PresentationDefinition;
import io.mosip.certify.core.dto.VerifyVpResponse;
import io.mosip.certify.core.exception.CertifyException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

import static org.junit.Assert.assertEquals;

@RunWith(MockitoJUnitRunner.class)
public class IarVpRequestServiceTest {

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private VerifiablePresentationRequestService vpRequestService;

    @InjectMocks
    private IarVpRequestService iarVpRequestService;

    @Before
    public void setup() {
        ReflectionTestUtils.setField(iarVpRequestService, "iaePostResponseMode", "iae_post");
        ReflectionTestUtils.setField(iarVpRequestService, "iaePostJwtResponseMode", "iae_post.jwt");
        ReflectionTestUtils.setField(iarVpRequestService, "certifyIaeEndpoint", "http://localhost:8090/v1/certify/oauth/iae");
    }

    @Test
    public void should_mapDirectPostToIaePost_when_responseModeIsDirectPost() {
        VerifyVpResponse verifyResponse = buildVerifyVpResponse("direct_post");
        InteractiveAuthorizationRequest iarRequest = buildIarRequest();

        Map<String, Object> result = (Map<String, Object>) iarVpRequestService.convertToOpenId4VpRequest(verifyResponse, iarRequest);

        assertEquals("iae_post", result.get("response_mode"));
        assertEquals("vp_token", result.get("response_type"));
        assertEquals("test-client", result.get("client_id"));
    }

    @Test
    public void should_mapDirectPostJwtToIaePostJwt_when_responseModeIsDirectPostJwt() {
        VerifyVpResponse verifyResponse = buildVerifyVpResponse("direct_post.jwt");
        InteractiveAuthorizationRequest iarRequest = buildIarRequest();

        Map<String, Object> result = (Map<String, Object>) iarVpRequestService.convertToOpenId4VpRequest(verifyResponse, iarRequest);

        assertEquals("iae_post.jwt", result.get("response_mode"));
    }

    @Test
    public void should_passThroughResponseMode_when_modeIsUnknown() {
        VerifyVpResponse verifyResponse = buildVerifyVpResponse("some_other_mode");
        InteractiveAuthorizationRequest iarRequest = buildIarRequest();

        Map<String, Object> result = (Map<String, Object>) iarVpRequestService.convertToOpenId4VpRequest(verifyResponse, iarRequest);

        assertEquals("some_other_mode", result.get("response_mode"));
    }

    @Test(expected = CertifyException.class)
    public void should_throwCertifyException_when_responseModeIsEmpty() {
        VerifyVpResponse verifyResponse = buildVerifyVpResponse("");
        InteractiveAuthorizationRequest iarRequest = buildIarRequest();

        iarVpRequestService.convertToOpenId4VpRequest(verifyResponse, iarRequest);
    }

    @Test(expected = CertifyException.class)
    public void should_throwCertifyException_when_authorizationDetailsAreNull() {
        VerifyVpResponse verifyResponse = new VerifyVpResponse();
        verifyResponse.setAuthorizationDetails(null);
        InteractiveAuthorizationRequest iarRequest = buildIarRequest();

        iarVpRequestService.convertToOpenId4VpRequest(verifyResponse, iarRequest);
    }

    private VerifyVpResponse buildVerifyVpResponse(String responseMode) {
        VerifyVpResponse response = new VerifyVpResponse();
        VerifyVpResponse.AuthorizationDetails authDetails = new VerifyVpResponse.AuthorizationDetails();
        authDetails.setResponseType("vp_token");
        authDetails.setResponseMode(responseMode);
        authDetails.setClientId("test-client");
        authDetails.setNonce("test-nonce");
        authDetails.setPresentationDefinition(new PresentationDefinition());
        response.setAuthorizationDetails(authDetails);
        return response;
    }

    private InteractiveAuthorizationRequest buildIarRequest() {
        InteractiveAuthorizationRequest request = new InteractiveAuthorizationRequest();
        request.setClientId("test-client");
        request.setResponseType("code");
        request.setCodeChallenge("test-challenge");
        request.setCodeChallengeMethod("S256");
        return request;
    }
}


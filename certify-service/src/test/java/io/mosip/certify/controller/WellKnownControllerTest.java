package io.mosip.certify.controller;

import com.jayway.jsonpath.JsonPath;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.JwksService;
import io.mosip.certify.core.spi.VCIssuanceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(WellKnownController.class)
class WellKnownControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CredentialConfigurationService credentialConfigurationService;

    @MockBean
    private VCIssuanceService vcIssuanceService;

    @MockBean
    private ParsedAccessToken parsedAccessToken;

    // AccessTokenValidationFilter is a @Component, so the web slice builds it
    // and every collaborator it autowires has to exist here too.
    @MockBean
    private io.mosip.certify.dpop.DpopProofValidator dpopProofValidator;

    @MockBean
    private JwksService jwksService;

    @InjectMocks
    private WellKnownController wellKnownController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void should_returnIssuerMetadata_when_metadataIsAvailable() throws Exception {
        CredentialIssuerMetadataDTO mockMetadata = mock(CredentialIssuerMetadataDTO.class);
        when(credentialConfigurationService.fetchCredentialIssuerMetadata()).thenReturn(mockMetadata);
        mockMvc.perform(get("/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk());
        verify(credentialConfigurationService, times(1)).fetchCredentialIssuerMetadata();
    }

    @Test
    void should_returnDidDocument_when_documentIsAvailable() throws Exception {
        Map<String, Object> mockDidDoc = Collections.singletonMap("id", "did:example:123");
        when(vcIssuanceService.getDIDDocument()).thenReturn(mockDidDoc);
        mockMvc.perform(get("/.well-known/did.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("did:example:123"));
    }

    @Test
    void should_returnNotFound_when_didDocumentIsNull() throws Exception {
        when(vcIssuanceService.getDIDDocument()).thenReturn(null);

        for (String accept : List.of(MediaType.APPLICATION_JSON_VALUE, "application/jwt")) {
            mockMvc.perform(get("/.well-known/did.json").accept(accept))
                    .andExpect(status().isNotFound())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.errors[0].errorCode").value("did_document_not_found"));
        }
    }

    @Test
    void should_returnError_when_didDocumentServiceThrows() throws Exception {
        when(vcIssuanceService.getDIDDocument()).thenThrow(new InvalidRequestException("unsupported_in_current_plugin_mode"));
        mockMvc.perform(get("/.well-known/did.json"))
                .andExpect(status().is2xxSuccessful())
                .andExpect(jsonPath("$.errors[0].errorCode").value("unsupported_in_current_plugin_mode"));
    }

    @Test
    void should_returnJwkSet_when_keysAreAvailable() throws Exception {
        Map<String, Object> mockJwks = Map.of(
                "keys", Collections.singletonList(
                        Map.of(
                                "kty", "RSA",
                                "kid", "test-key-id",
                                "use", "sig",
                                "n", "test-modulus",
                                "e", "AQAB"
                        )
                )
        );
        when(jwksService.getJwks()).thenReturn(mockJwks);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").value("test-key-id"));

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void should_returnEmptyKeys_when_keysListIsEmpty() throws Exception {
        Map<String, Object> emptyJwks = Map.of("keys", Collections.emptyList());
        when(jwksService.getJwks()).thenReturn(emptyJwks);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void should_returnServiceUnavailable_when_jwksIsNull() throws Exception {
        when(jwksService.getJwks()).thenReturn(null);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void should_returnServiceUnavailable_when_keysFieldIsMissing() throws Exception {
        Map<String, Object> invalidResponse = Collections.singletonMap("invalid", "response");
        when(jwksService.getJwks()).thenReturn(invalidResponse);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void should_returnServiceUnavailable_when_jwksServiceThrows() throws Exception {
        when(jwksService.getJwks()).thenThrow(new RuntimeException("Keymanager service unavailable"));

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void should_returnNullKeys_when_keysListIsNull() throws Exception {
        Map<String, Object> nullKeysResponse = Collections.singletonMap("keys", null);
        when(jwksService.getJwks()).thenReturn(nullKeysResponse);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").doesNotExist());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void should_returnAllKeys_when_thereAreMultipleKeys() throws Exception {
        Map<String, Object> mockJwks = Map.of(
                "keys", List.of(
                        Map.of("kty", "RSA", "kid", "key1", "use", "sig"),
                        Map.of("kty", "EC", "kid", "key2", "use", "sig")
                )
        );
        when(jwksService.getJwks()).thenReturn(mockJwks);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys.length()").value(2))
                .andExpect(jsonPath("$.keys[0].kid").value("key1"))
                .andExpect(jsonPath("$.keys[1].kid").value("key2"));

        verify(jwksService, times(1)).getJwks();
    }

    @ParameterizedTest(name = "Accept: {0}")
    @MethodSource(WellKnownResponseAssertions.ACCEPT_VALUES)
    void should_returnJsonIssuerMetadata_when_acceptIsAnyMediaType(String accept) throws Exception {
        CredentialIssuerMetadataDTO metadata = new CredentialIssuerMetadataDTO();
        metadata.setCredentialIssuer("http://localhost:8090");
        metadata.setCredentialEndpoint("http://localhost:8090/v1/certify/issuance/credential");
        metadata.setNonceEndpoint("http://localhost:8090/v1/certify/nonce");
        when(credentialConfigurationService.fetchCredentialIssuerMetadata()).thenReturn(metadata);

        WellKnownResponseAssertions.assertServesJsonDocument(mockMvc, "/.well-known/openid-credential-issuer", accept);
    }

    @ParameterizedTest(name = "Accept: {0}")
    @MethodSource(WellKnownResponseAssertions.ACCEPT_VALUES)
    void should_returnJsonDidDocument_when_acceptIsAnyMediaType(String accept) throws Exception {
        when(vcIssuanceService.getDIDDocument()).thenReturn(Collections.singletonMap("id", "did:example:123"));

        WellKnownResponseAssertions.assertServesJsonDocument(mockMvc, "/.well-known/did.json", accept);
    }

    @ParameterizedTest(name = "Accept: {0}")
    @MethodSource(WellKnownResponseAssertions.ACCEPT_VALUES)
    void should_returnJsonJwkSet_when_acceptIsAnyMediaType(String accept) throws Exception {
        when(jwksService.getJwks()).thenReturn(Map.of(
                "keys", Collections.singletonList(Map.of("kty", "RSA", "kid", "test-key-id", "e", "AQAB"))));

        WellKnownResponseAssertions.assertServesJsonDocument(mockMvc, "/.well-known/jwks.json", accept);
    }

    @Test
    void should_returnJsonServiceUnavailable_when_acceptIsApplicationJwtAndJwksIsNull() throws Exception {
        when(jwksService.getJwks()).thenReturn(null);

        mockMvc.perform(get("/.well-known/jwks.json").accept("application/jwt"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());
    }

    @Test
    void should_returnJsonError_when_didDocumentThrowsAndAcceptIsApplicationJwt() throws Exception {
        // In VCIssuance plugin mode did.json always throws this error
        when(vcIssuanceService.getDIDDocument()).thenThrow(new InvalidRequestException("unsupported_in_current_plugin_mode"));

        MockHttpServletResponse json = mockMvc.perform(get("/.well-known/did.json").accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.errors[0].errorCode").value("unsupported_in_current_plugin_mode"))
                .andReturn().getResponse();
        List<Object> errors = JsonPath.read(json.getContentAsString(), "$.errors");

        mockMvc.perform(get("/.well-known/did.json").accept("application/jwt"))
                .andExpect(status().is(json.getStatus()))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.errors").value(errors));
    }
}
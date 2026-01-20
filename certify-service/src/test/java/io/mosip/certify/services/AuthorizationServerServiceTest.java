package io.mosip.certify.services;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.AuthorizationServerMetadata;
import io.mosip.certify.core.dto.OAuthAuthorizationServerMetadataDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AuthorizationServerService.
 * Tests the consolidated authorization server management where:
 * - Primary server URL comes from OAuthAuthorizationServerMetadataService (no config duplication)
 * - Additional external servers can be configured separately
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthorizationServerServiceTest {

    @Mock
    private VCICacheService vciCacheService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private OAuthAuthorizationServerMetadataService oAuthMetadataService;

    @InjectMocks
    private AuthorizationServerService authorizationServerService;

    private static final String PRIMARY_SERVER_URL = "https://primary-auth.example.com";
    private static final String EXTERNAL_SERVER_URL = "https://external-auth.example.com";
    private static final String DEFAULT_SERVER_URL = "https://default-auth.example.com";

    @Before
    public void setup() {
        ReflectionTestUtils.setField(authorizationServerService, "retryCount", 3);
        ReflectionTestUtils.setField(authorizationServerService, "externalServersConfig", "");
        ReflectionTestUtils.setField(authorizationServerService, "defaultAuthServer", "");
        ReflectionTestUtils.setField(authorizationServerService, "credentialConfigMappingJson", "{}");

        // Mock the primary server from OAuthAuthorizationServerMetadataService
        OAuthAuthorizationServerMetadataDTO primaryMetadata = new OAuthAuthorizationServerMetadataDTO();
        primaryMetadata.setIssuer(PRIMARY_SERVER_URL);
        primaryMetadata.setTokenEndpoint(PRIMARY_SERVER_URL + "/token");
        when(oAuthMetadataService.getOAuthAuthorizationServerMetadata()).thenReturn(primaryMetadata);
    }

    // ========== Tests for initialize() - Primary Server from OAuthAuthorizationServerMetadataService ==========

    @Test
    public void initialize_LoadsPrimaryServerFromOAuthMetadataService() {
        authorizationServerService.initialize();

        List<String> urls = authorizationServerService.getAllAuthorizationServerUrls();
        assertEquals(1, urls.size());
        assertEquals(PRIMARY_SERVER_URL, urls.get(0));
        
        // Verify we're using the merged service
        verify(oAuthMetadataService).getOAuthAuthorizationServerMetadata();
    }

    @Test
    public void initialize_WithExternalServers_AddsToServerList() {
        ReflectionTestUtils.setField(authorizationServerService, "externalServersConfig", EXTERNAL_SERVER_URL);

        authorizationServerService.initialize();

        List<String> urls = authorizationServerService.getAllAuthorizationServerUrls();
        assertEquals(2, urls.size()); // primary + external
        assertTrue(urls.contains(PRIMARY_SERVER_URL));
        assertTrue(urls.contains(EXTERNAL_SERVER_URL));
    }

    @Test
    public void initialize_WithDuplicateExternalServer_AvoidsDuplication() {
        // External server is same as primary - should not add duplicate
        ReflectionTestUtils.setField(authorizationServerService, "externalServersConfig", PRIMARY_SERVER_URL);

        authorizationServerService.initialize();

        List<String> urls = authorizationServerService.getAllAuthorizationServerUrls();
        assertEquals(1, urls.size()); // Only primary, no duplicate
    }

    @Test
    public void initialize_WhenOAuthMetadataServiceFails_ContinuesWithEmpty() {
        when(oAuthMetadataService.getOAuthAuthorizationServerMetadata())
                .thenThrow(new RuntimeException("Service unavailable"));

        authorizationServerService.initialize();

        List<String> urls = authorizationServerService.getAllAuthorizationServerUrls();
        assertEquals(0, urls.size());
    }

    @Test
    public void initialize_WithEmptyExternalConfig_OnlyPrimaryAdded() {
        ReflectionTestUtils.setField(authorizationServerService, "externalServersConfig", "  ,  ");

        authorizationServerService.initialize();

        List<String> urls = authorizationServerService.getAllAuthorizationServerUrls();
        assertEquals(1, urls.size());
        assertEquals(PRIMARY_SERVER_URL, urls.get(0));
    }

    // ========== Tests for loadCredentialConfigMappings() ==========

    @Test
    public void initialize_WithCredentialConfigMappings_Success() throws Exception {
        String mappingJson = "{\"config1\":\"https://auth1.example.com\",\"config2\":\"https://auth2.example.com\"}";
        ReflectionTestUtils.setField(authorizationServerService, "credentialConfigMappingJson", mappingJson);

        when(objectMapper.readValue(eq(mappingJson), any(TypeReference.class)))
                .thenReturn(Map.of("config1", "https://auth1.example.com", "config2", "https://auth2.example.com"));

        authorizationServerService.initialize();

        verify(objectMapper).readValue(eq(mappingJson), any(TypeReference.class));
    }

    @Test
    public void initialize_WithInvalidCredentialConfigMappings_NoException() throws Exception {
        String mappingJson = "invalid-json";
        ReflectionTestUtils.setField(authorizationServerService, "credentialConfigMappingJson", mappingJson);

        when(objectMapper.readValue(eq(mappingJson), any(TypeReference.class)))
                .thenThrow(new RuntimeException("Invalid JSON"));

        // Should not throw, just log error
        authorizationServerService.initialize();
    }

    // ========== Tests for discoverMetadata() ==========

    @Test
    public void discoverMetadata_CacheHit_ReturnsCachedMetadata() {
        // Configure external server so validateServerConfigured passes
        ReflectionTestUtils.setField(authorizationServerService, "externalServersConfig", EXTERNAL_SERVER_URL);
        authorizationServerService.initialize();

        AuthorizationServerMetadata cachedMetadata = AuthorizationServerMetadata.builder()
                .issuer(EXTERNAL_SERVER_URL)
                .tokenEndpoint(EXTERNAL_SERVER_URL + "/token")
                .build();

        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(cachedMetadata);

        AuthorizationServerMetadata result = authorizationServerService.discoverMetadata(EXTERNAL_SERVER_URL);

        assertEquals(cachedMetadata, result);
        verify(restTemplate, never()).getForEntity(any(URI.class), eq(String.class));
    }

    @Test
    public void discoverMetadata_CacheMiss_DiscoverFromOIDC_Success() throws Exception {
        // Configure external server so validateServerConfigured passes
        ReflectionTestUtils.setField(authorizationServerService, "externalServersConfig", EXTERNAL_SERVER_URL);
        authorizationServerService.initialize();

        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(null);

        String metadataJson = "{\"issuer\":\"" + EXTERNAL_SERVER_URL + "\",\"token_endpoint\":\"" + EXTERNAL_SERVER_URL + "/token\"}";
        ResponseEntity<String> response = new ResponseEntity<>(metadataJson, HttpStatus.OK);

        when(restTemplate.getForEntity(any(URI.class), eq(String.class))).thenReturn(response);

        AuthorizationServerMetadata expectedMetadata = AuthorizationServerMetadata.builder()
                .issuer(EXTERNAL_SERVER_URL)
                .tokenEndpoint(EXTERNAL_SERVER_URL + "/token")
                .build();

        when(objectMapper.readValue(eq(metadataJson), eq(AuthorizationServerMetadata.class)))
                .thenReturn(expectedMetadata);

        AuthorizationServerMetadata result = authorizationServerService.discoverMetadata(EXTERNAL_SERVER_URL);

        assertNotNull(result);
        assertEquals(EXTERNAL_SERVER_URL, result.getIssuer());
        verify(vciCacheService).setASMetadata(eq(EXTERNAL_SERVER_URL), eq(expectedMetadata));
    }

    @Test
    public void discoverMetadata_AllAttemptsFail_ThrowsCertifyException() throws Exception {
        // Configure external server so validateServerConfigured passes
        ReflectionTestUtils.setField(authorizationServerService, "externalServersConfig", EXTERNAL_SERVER_URL);
        authorizationServerService.initialize();

        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(null);

        ResponseEntity<String> failedResponse = new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
        when(restTemplate.getForEntity(any(URI.class), eq(String.class))).thenReturn(failedResponse);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> authorizationServerService.discoverMetadata(EXTERNAL_SERVER_URL));

        assertEquals(ErrorConstants.AUTHORIZATION_SERVER_DISCOVERY_FAILED, exception.getErrorCode());
    }

    // ========== Tests for getTokenEndpoint() ==========

    @Test
    public void getTokenEndpoint_Success() {
        // Configure external server so validateServerConfigured passes
        ReflectionTestUtils.setField(authorizationServerService, "externalServersConfig", EXTERNAL_SERVER_URL);
        authorizationServerService.initialize();

        AuthorizationServerMetadata metadata = AuthorizationServerMetadata.builder()
                .issuer(EXTERNAL_SERVER_URL)
                .tokenEndpoint(EXTERNAL_SERVER_URL + "/token")
                .build();

        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(metadata);

        String tokenEndpoint = authorizationServerService.getTokenEndpoint(EXTERNAL_SERVER_URL);

        assertEquals(EXTERNAL_SERVER_URL + "/token", tokenEndpoint);
    }

    // ========== Tests for supportsPreAuthorizedCodeGrant() ==========

    @Test
    public void supportsPreAuthorizedCodeGrant_Supported_ReturnsTrue() {
        // Configure external server so validateServerConfigured passes
        ReflectionTestUtils.setField(authorizationServerService, "externalServersConfig", EXTERNAL_SERVER_URL);
        authorizationServerService.initialize();

        AuthorizationServerMetadata metadata = AuthorizationServerMetadata.builder()
                .issuer(EXTERNAL_SERVER_URL)
                .tokenEndpoint(EXTERNAL_SERVER_URL + "/token")
                .grantTypesSupported(Arrays.asList("authorization_code", Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE))
                .build();

        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(metadata);

        boolean result = authorizationServerService.supportsPreAuthorizedCodeGrant(EXTERNAL_SERVER_URL);

        assertTrue(result);
    }

    @Test
    public void supportsPreAuthorizedCodeGrant_NotSupported_ReturnsFalse() {
        // Configure external server so validateServerConfigured passes
        ReflectionTestUtils.setField(authorizationServerService, "externalServersConfig", EXTERNAL_SERVER_URL);
        authorizationServerService.initialize();

        AuthorizationServerMetadata metadata = AuthorizationServerMetadata.builder()
                .issuer(EXTERNAL_SERVER_URL)
                .tokenEndpoint(EXTERNAL_SERVER_URL + "/token")
                .grantTypesSupported(Arrays.asList("authorization_code"))
                .build();

        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(metadata);

        boolean result = authorizationServerService.supportsPreAuthorizedCodeGrant(EXTERNAL_SERVER_URL);

        assertFalse(result);
    }

    // ========== Tests for getAuthorizationServerForCredentialConfig() ==========

    @Test
    public void getAuthorizationServerForCredentialConfig_NoMapping_UsesPrimary() {
        String configId = "some-config";

        authorizationServerService.initialize();

        String result = authorizationServerService.getAuthorizationServerForCredentialConfig(configId);

        assertEquals(PRIMARY_SERVER_URL, result);
    }

    @Test
    public void getAuthorizationServerForCredentialConfig_NoMapping_UsesDefault() throws Exception {
        String configId = "unmapped-config";

        // Add default server to configured servers list so validation passes
        ReflectionTestUtils.setField(authorizationServerService, "externalServersConfig", DEFAULT_SERVER_URL);
        ReflectionTestUtils.setField(authorizationServerService, "defaultAuthServer", DEFAULT_SERVER_URL);

        authorizationServerService.initialize();

        String result = authorizationServerService.getAuthorizationServerForCredentialConfig(configId);

        assertEquals(DEFAULT_SERVER_URL, result);
    }

    @Test
    public void getAuthorizationServerForCredentialConfig_MappedAS_ReturnsMapping() throws Exception {
        String configId = "test-config";

        ReflectionTestUtils.setField(authorizationServerService, "credentialConfigMappingJson",
                "{\"" + configId + "\":\"" + PRIMARY_SERVER_URL + "\"}");

        when(objectMapper.readValue(anyString(), any(TypeReference.class)))
                .thenReturn(Map.of(configId, PRIMARY_SERVER_URL));

        authorizationServerService.initialize();

        String result = authorizationServerService.getAuthorizationServerForCredentialConfig(configId);

        assertEquals(PRIMARY_SERVER_URL, result);
    }

    @Test
    public void getAuthorizationServerForCredentialConfig_NoASConfigured_ThrowsCertifyException() {
        String configId = "some-config";

        when(oAuthMetadataService.getOAuthAuthorizationServerMetadata())
                .thenThrow(new RuntimeException("Service unavailable"));
        ReflectionTestUtils.setField(authorizationServerService, "defaultAuthServer", "");

        authorizationServerService.initialize();

        CertifyException exception = assertThrows(CertifyException.class,
                () -> authorizationServerService.getAuthorizationServerForCredentialConfig(configId));

        assertEquals(ErrorConstants.AUTHORIZATION_SERVER_NOT_CONFIGURED, exception.getErrorCode());
    }

    @Test
    public void getAuthorizationServerForCredentialConfig_MappedButNotConfigured_ThrowsInvalidRequestException() throws Exception {
        String configId = "test-config";
        String unconfiguredUrl = "https://unconfigured.example.com";

        ReflectionTestUtils.setField(authorizationServerService, "credentialConfigMappingJson",
                "{\"" + configId + "\":\"" + unconfiguredUrl + "\"}");

        when(objectMapper.readValue(anyString(), any(TypeReference.class)))
                .thenReturn(Map.of(configId, unconfiguredUrl));

        authorizationServerService.initialize();

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> authorizationServerService.getAuthorizationServerForCredentialConfig(configId));

        assertEquals(ErrorConstants.INVALID_AUTHORIZATION_SERVER, exception.getErrorCode());
    }

    // ========== Tests for getAllAuthorizationServerUrls() ==========

    @Test
    public void getAllAuthorizationServerUrls_ReturnsAllConfigured() {
        ReflectionTestUtils.setField(authorizationServerService, "externalServersConfig",
                EXTERNAL_SERVER_URL + ", " + DEFAULT_SERVER_URL);

        authorizationServerService.initialize();

        List<String> urls = authorizationServerService.getAllAuthorizationServerUrls();

        assertEquals(3, urls.size()); // primary + 2 external
        assertTrue(urls.contains(PRIMARY_SERVER_URL));
        assertTrue(urls.contains(EXTERNAL_SERVER_URL));
        assertTrue(urls.contains(DEFAULT_SERVER_URL));
    }

    // ========== Tests for isServerConfigured() ==========

    @Test
    public void isServerConfigured_ConfiguredServer_ReturnsTrue() {
        authorizationServerService.initialize();

        boolean result = authorizationServerService.isServerConfigured(PRIMARY_SERVER_URL);

        assertTrue(result);
    }

    @Test
    public void isServerConfigured_ConfiguredServerWithTrailingSlash_ReturnsTrue() {
        authorizationServerService.initialize();

        boolean result = authorizationServerService.isServerConfigured(PRIMARY_SERVER_URL + "/");

        assertTrue(result);
    }

    @Test
    public void isServerConfigured_UnconfiguredServer_ReturnsFalse() {
        authorizationServerService.initialize();

        boolean result = authorizationServerService.isServerConfigured("https://unknown.example.com");

        assertFalse(result);
    }

    // ========== Tests for normalizeUrl() ==========

    @Test
    public void normalizeUrl_RemovesTrailingSlash() {
        authorizationServerService.initialize();

        String result = ReflectionTestUtils.invokeMethod(authorizationServerService, "normalizeUrl",
                "https://example.com/");

        assertEquals("https://example.com", result);
    }

    @Test
    public void normalizeUrl_NullUrl_ReturnsEmptyString() {
        authorizationServerService.initialize();

        String result = ReflectionTestUtils.invokeMethod(authorizationServerService, "normalizeUrl",
                (String) null);

        assertEquals("", result);
    }

    // ========== Tests for generateServerId() ==========

    @Test
    public void generateServerId_ValidUrl_GeneratesId() {
        authorizationServerService.initialize();

        String result = ReflectionTestUtils.invokeMethod(authorizationServerService, "generateServerId",
                "https://auth.example.com");

        assertNotNull(result);
        assertTrue(result.startsWith("as-"));
        assertTrue(result.contains("auth-example-com"));
    }
}

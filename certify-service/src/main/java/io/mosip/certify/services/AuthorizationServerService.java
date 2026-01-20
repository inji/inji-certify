package io.mosip.certify.services;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.AuthorizationServerConfig;
import io.mosip.certify.core.dto.AuthorizationServerMetadata;
import io.mosip.certify.core.dto.OAuthAuthorizationServerMetadataDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for managing authorization servers.
 * All authorization servers are treated uniformly.
 * 
 * Uses OAuthAuthorizationServerMetadataService to get the primary/internal server URL,
 * avoiding config property duplication.
 */
@Service
@Slf4j
public class AuthorizationServerService {

    @Autowired
    private VCICacheService vciCacheService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private OAuthAuthorizationServerMetadataService oAuthMetadataService;

    @Value("${mosip.certify.authorization.discovery.retry-count:3}")
    private int retryCount;

    @Value("${mosip.certify.authorization.external-servers:}")
    private String externalServersConfig;

    @Value("${mosip.certify.authorization.default-server:}")
    private String defaultAuthServer;

    /**
     * JSON mapping of credential configuration IDs to authorization server URLs.
     * Format: {"configId1": "https://as1.example.com", "configId2": "https://as2.example.com"}
     */
    @Value("${mosip.certify.credential-config.as-mapping:{}}")
    private String credentialConfigMappingJson;

    private List<AuthorizationServerConfig> configuredServers;
    private Map<String, String> credentialConfigToASMapping;

    @PostConstruct
    public void initialize() {
        log.info("Initializing Authorization Server Service");

        configuredServers = new ArrayList<>();
        loadConfiguredServers();
        loadCredentialConfigMappings();

        log.info("Configured {} authorization servers", configuredServers.size());
        log.info("Loaded {} credential configuration mappings", credentialConfigToASMapping.size());
    }

    /**
     * Load all configured authorization servers.
     * Primary server comes from OAuthAuthorizationServerMetadataService (reusing config).
     * Additional external servers can be configured separately.
     */
    private void loadConfiguredServers() {
        // 1. Get primary server from OAuthAuthorizationServerMetadataService (avoids config duplication)
        try {
            OAuthAuthorizationServerMetadataDTO internalMetadata = oAuthMetadataService.getOAuthAuthorizationServerMetadata();
            String primaryServerUrl = internalMetadata.getIssuer();
            
            if (StringUtils.hasText(primaryServerUrl)) {
                AuthorizationServerConfig primaryConfig = AuthorizationServerConfig.builder()
                        .serverId("primary")
                        .serverUrl(normalizeUrl(primaryServerUrl))
                        .build();
                configuredServers.add(primaryConfig);
                log.info("Added primary authorization server from OAuth config: {}", primaryServerUrl);
            }
        } catch (Exception e) {
            log.warn("Could not load primary authorization server from OAuthAuthorizationServerMetadataService: {}", 
                    e.getMessage());
        }

        // 2. Add any additional external servers
        if (StringUtils.hasText(externalServersConfig)) {
            String[] servers = externalServersConfig.split(",");
            for (String serverUrl : servers) {
                serverUrl = serverUrl.trim();
                if (StringUtils.hasText(serverUrl)) {
                    // Avoid duplicates
                    String normalizedUrl = normalizeUrl(serverUrl);
                    boolean alreadyExists = configuredServers.stream()
                            .anyMatch(c -> c.getServerUrl().equals(normalizedUrl));
                    
                    if (!alreadyExists) {
                        AuthorizationServerConfig config = AuthorizationServerConfig.builder()
                                .serverId(generateServerId(serverUrl))
                                .serverUrl(normalizedUrl)
                                .build();
                        configuredServers.add(config);
                        log.info("Added external authorization server: {}", serverUrl);
                    }
                }
            }
        }

        if (configuredServers.isEmpty()) {
            log.warn("No authorization servers configured. Ensure mosip.certify.oauth.issuer is set.");
        }
    }

    private void loadCredentialConfigMappings() {
        credentialConfigToASMapping = new HashMap<>();

        try {
            if (StringUtils.hasText(credentialConfigMappingJson) &&
                    !credentialConfigMappingJson.trim().equals("{}")) {

                Map<String, String> mappings = objectMapper.readValue(
                        credentialConfigMappingJson,
                        new TypeReference<Map<String, String>>() {
                        });

                credentialConfigToASMapping.putAll(mappings);
                log.info("Loaded credential config mappings: {}", mappings);
            }
        } catch (Exception e) {
            log.error("Failed to parse credential config mappings. Credential-to-AS mappings will be empty. " +
                    "Check mosip.certify.credential-config.as-mapping property format.", e);
        }
    }

    /**
     * Discover authorization server metadata from well-known endpoint.
     * Tries OIDC configuration first, then falls back to OAuth AS metadata.
     */
    public AuthorizationServerMetadata discoverMetadata(String serverUrl) {
        log.info("Discovering authorization server metadata for: {}", serverUrl);

        // SSRF protection: validate server URL is in configured allowlist
        validateServerConfigured(serverUrl);

        // Check cache first
        AuthorizationServerMetadata cached = vciCacheService.getASMetadata(serverUrl);
        if (cached != null) {
            log.info("Using cached AS metadata for: {}", serverUrl);
            return cached;
        }

        // Try OIDC config first (per RFC 8414 compatibility notes), then OAuth AS discovery
        AuthorizationServerMetadata metadata = tryDiscoveryEndpoint(serverUrl, "/.well-known/openid-configuration");
        if (metadata == null) {
            log.info("OIDC configuration discovery failed, trying OAuth AS endpoint");
            metadata = tryDiscoveryEndpoint(serverUrl, "/.well-known/oauth-authorization-server");
        }

        if (metadata == null) {
            log.error("Failed to discover AS metadata for: {}", serverUrl);
            throw new CertifyException(ErrorConstants.AUTHORIZATION_SERVER_DISCOVERY_FAILED,
                    "Could not discover authorization server metadata");
        }

        // Cache the metadata
        vciCacheService.setASMetadata(serverUrl, metadata);
        log.info("Successfully discovered and cached AS metadata for: {}", serverUrl);

        return metadata;
    }

    private AuthorizationServerMetadata tryDiscoveryEndpoint(String serverUrl, String wellKnownPath) {
        String discoveryUrl = normalizeUrl(serverUrl) + wellKnownPath;

        for (int attempt = 1; attempt <= retryCount; attempt++) {
            try {
                log.debug("Discovery attempt {} for URL: {}", attempt, discoveryUrl);

                ResponseEntity<String> response = restTemplate.getForEntity(new URI(discoveryUrl), String.class);

                if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                    AuthorizationServerMetadata metadata = objectMapper.readValue(
                            response.getBody(),
                            AuthorizationServerMetadata.class);

                    validateMetadata(metadata, serverUrl);
                    return metadata;
                }
            } catch (Exception e) {
                log.warn("Discovery attempt {} failed for {}: {}", attempt, discoveryUrl, e.getMessage());
                if (attempt == retryCount) {
                    log.error("All discovery attempts failed for: {}", discoveryUrl, e);
                }
            }
        }
        return null;
    }

    private void validateMetadata(AuthorizationServerMetadata metadata, String expectedIssuer) {
        if (metadata == null
                || !StringUtils.hasText(metadata.getIssuer())
                || !StringUtils.hasText(metadata.getTokenEndpoint())) {
            throw new CertifyException(ErrorConstants.AUTHORIZATION_SERVER_DISCOVERY_FAILED);
        }

        // Validate issuer matches expected URL
        String normalizedExpected = normalizeUrl(expectedIssuer);
        String normalizedActual = normalizeUrl(metadata.getIssuer());

        if (!normalizedActual.equals(normalizedExpected)) {
            log.warn("Issuer mismatch: expected {}, got {}", normalizedExpected, normalizedActual);
        }
    }

    /**
     * Get token endpoint for a specific authorization server.
     */
    public String getTokenEndpoint(String serverUrl) {
        AuthorizationServerMetadata metadata = discoverMetadata(serverUrl);
        return metadata.getTokenEndpoint();
    }

    /**
     * Check if authorization server supports pre-authorized code grant.
     */
    public boolean supportsPreAuthorizedCodeGrant(String serverUrl) {
        try {
            AuthorizationServerMetadata metadata = discoverMetadata(serverUrl);
            List<String> grantTypes = metadata.getGrantTypesSupported();
            return grantTypes != null && grantTypes.contains(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        } catch (Exception e) {
            log.warn("Could not check grant type support for {}: {}", serverUrl, e.getMessage());
            return false;
        }
    }

    /**
     * Get authorization server URL for a specific credential configuration.
     * Resolution order:
     * 1. Specific mapping in credential-config.as-mapping
     * 2. Default server from authorization.default-server
     * 3. Primary server (first configured, from OAuthAuthorizationServerMetadataService)
     */
    public String getAuthorizationServerForCredentialConfig(String credentialConfigId) {
        log.debug("Getting authorization server for credential config: {}", credentialConfigId);

        // 1. Check if there's a specific mapping
        String mappedServerUrl = credentialConfigToASMapping.get(credentialConfigId);
        if (StringUtils.hasText(mappedServerUrl)) {
            validateServerConfigured(mappedServerUrl);
            log.debug("Found mapped AS for {}: {}", credentialConfigId, mappedServerUrl);
            return mappedServerUrl;
        }

        // 2. Use default server if configured
        if (StringUtils.hasText(defaultAuthServer)) {
            validateServerConfigured(defaultAuthServer);
            log.debug("Using default AS for {}: {}", credentialConfigId, defaultAuthServer);
            return defaultAuthServer;
        }

        // 3. Fall back to primary server (first configured)
        if (!configuredServers.isEmpty()) {
            String primaryServer = configuredServers.get(0).getServerUrl();
            log.debug("Using primary AS for {}: {}", credentialConfigId, primaryServer);
            return primaryServer;
        }

        log.error("No authorization server found for credential config: {}", credentialConfigId);
        throw new CertifyException(ErrorConstants.AUTHORIZATION_SERVER_NOT_CONFIGURED,
                "No authorization server configured for credential configuration: " + credentialConfigId);
    }

    /**
     * Get all configured authorization server URLs.
     */
    public List<String> getAllAuthorizationServerUrls() {
        return configuredServers.stream()
                .map(AuthorizationServerConfig::getServerUrl)
                .collect(Collectors.toList());
    }

    /**
     * Check if a server URL is configured.
     */
    public boolean isServerConfigured(String serverUrl) {
        String normalized = normalizeUrl(serverUrl);
        return configuredServers.stream()
                .anyMatch(config -> normalizeUrl(config.getServerUrl()).equals(normalized));
    }

    private void validateServerConfigured(String serverUrl) {
        if (!isServerConfigured(serverUrl)) {
            log.error("Authorization server not configured: {}", serverUrl);
            throw new InvalidRequestException(ErrorConstants.INVALID_AUTHORIZATION_SERVER);
        }
    }

    /**
     * Normalize URL by removing trailing slashes.
     */
    private String normalizeUrl(String url) {
        if (url == null) {
            return "";
        }
        return url.replaceAll("/+$", "");
    }

    /**
     * Generate unique server ID from URL.
     */
    private String generateServerId(String serverUrl) {
        try {
            String normalized = normalizeUrl(serverUrl);
            String domain = normalized.replaceAll("https?://", "")
                    .replaceAll("[^a-zA-Z0-9-]", "-");
            return "as-" + domain;
        } catch (Exception e) {
            return "as-" + UUID.randomUUID().toString();
        }
    }
}
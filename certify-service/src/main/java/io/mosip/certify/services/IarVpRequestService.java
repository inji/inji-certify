/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.config.VerifyServiceConfig;
import io.mosip.certify.core.dto.InteractiveAuthorizationRequest;
import io.mosip.certify.core.dto.VerifyVpRequest;
import io.mosip.certify.core.dto.VerifyVpResponse;
import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Service for creating VP requests with verify service
 * Handles communication with VP Verifier service
 */
@Slf4j
@Service
public class IarVpRequestService {

    private final RestTemplate restTemplate;

    private final ObjectMapper objectMapper;

    @Value("${mosip.certify.vp-request.config-file-url:}")
    private String vpRequestConfigUrl;

    @Value("${mosip.certify.verify.service.vp-request-endpoint:}")
    private String verifyServiceVpRequestEndpoint;

    @Value("${mosip.certify.verify.service.verifier-client-id:}")
    private String verifierClientId;

    @Value("${mosip.certify.iar.response-mode.iar-post:iar-post}")
    private String iarPostResponseMode;

    @Value("${mosip.certify.oauth.interactive-authorization-endpoint:}")
    private String certifyIarEndpoint;

    @Value("${spring.profiles.active:}")
    private String activeProfile;

    @Autowired
    public IarVpRequestService(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }
    /**
     * Create VP request with verify service
     * 
     * @param iarRequest The interactive authorization request
     * @return VerifyVpResponse from verify service
     * @throws CertifyException if request fails
     */
    public VerifyVpResponse createVpRequest(InteractiveAuthorizationRequest iarRequest) throws CertifyException {
        log.info("Calling verify service for VP request generation for wallet client_id: {} using verifier client_id: {}",
                 iarRequest.getClientId(), verifierClientId);

        validateConfiguration();
        VerifyServiceConfig verifyServiceConfig;
        try {
            log.info("Fetching VP Request Config from : {}", vpRequestConfigUrl);
            String vpRequestConfig;
            if (activeProfile != null && activeProfile.contains("local")) {
                Resource resource = new ClassPathResource(vpRequestConfigUrl);
                try (var inputStream = resource.getInputStream()) {
                   vpRequestConfig = new String(inputStream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                }
            } else {
                vpRequestConfig = restTemplate.getForObject(vpRequestConfigUrl, String.class);
            }
            if (vpRequestConfig == null || vpRequestConfig.isBlank()) {
                throw new CertifyException("unknown_error", "VP request configuration is empty or unavailable");
            }
            verifyServiceConfig = objectMapper.readValue(vpRequestConfig, VerifyServiceConfig.class);
        } catch (IOException | org.springframework.web.client.RestClientException e) {
            log.error("Failed to load / parse vp request configuration", e);
            throw new CertifyException("unknown_error", "Failed to load / parse vp request configuration", e);
        }

        try {
            VerifyVpRequest verifyRequest = new VerifyVpRequest();
            verifyRequest.setClientId(verifierClientId);
            log.debug("Using verifier client_id: {} for VP request (wallet client_id: {})", 
                     verifierClientId, iarRequest.getClientId());
            verifyRequest.setResponseModesSupported(Arrays.asList(
                "direct-post", 
                "direct-post.jwt"
            ));
            verifyRequest.setEncryptionRequired(true);

            verifyRequest.setPresentationDefinition(verifyServiceConfig.getPresentationDefinition());

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<VerifyVpRequest> requestEntity = new HttpEntity<>(verifyRequest, headers);

            String verifyServiceUrl = verifyServiceVpRequestEndpoint;
            log.debug("Calling verify service at: {}", verifyServiceUrl);

            VerifyVpResponse verifyResponse = restTemplate.postForObject(
                verifyServiceUrl,
                requestEntity,
                VerifyVpResponse.class
            );
            if (verifyResponse == null) {
                throw new CertifyException("unknown_error", "Empty response from verify service");
            }

            log.info("Successfully received VP request from verify service for client_id: {}, transactionId: {}", 
                     iarRequest.getClientId(), verifyResponse.getTransactionId());

            return verifyResponse;

        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to call verify service for client_id: {}", iarRequest.getClientId(), e);
            throw new CertifyException("unknown_error", "Failed to call verify service", e);
        }
    }

    /**
     * Convert verify response to OpenID4VP request
     */
    public Object convertToOpenId4VpRequest(VerifyVpResponse verifyResponse, InteractiveAuthorizationRequest iarRequest) {
        // Create a Map to represent the OpenID4VP request structure
        Map<String, Object> openId4VpRequest = new HashMap<>();
        
        VerifyVpResponse.AuthorizationDetails authDetails = verifyResponse.getAuthorizationDetails();
        if (authDetails == null) {
            log.error("No authorization details found in verify service response - this is required for production");
            throw new CertifyException("unknown_error", "Invalid response from verify service: missing authorization details");
        }

        openId4VpRequest.put("response_type", authDetails.getResponseType());
        openId4VpRequest.put("client_id", authDetails.getClientId() != null ? authDetails.getClientId() : iarRequest.getClientId());
        
        openId4VpRequest.put("nonce", authDetails.getNonce());
        log.info("Forwarding VP request nonce from Verify: {}", authDetails.getNonce());
        
        openId4VpRequest.put("presentation_definition", authDetails.getPresentationDefinition());
        
        String responseMode = authDetails.getResponseMode();
        if (!StringUtils.hasText(responseMode)) {
            throw new CertifyException("unknown_error", "Response mode is required");
        }
        
        // Simple mapping
        if ("direct_post".equals(responseMode)) {
            responseMode = iarPostResponseMode;
        } else if ("direct_post.jwt".equals(responseMode)) {
            responseMode = "iar-post.jwt";
        }
        openId4VpRequest.put("response_mode", responseMode);
        
        openId4VpRequest.put("response_uri", certifyIarEndpoint);
        log.info("Using certify /iar endpoint for wallet VP submission: {}", certifyIarEndpoint);

        log.info("Successfully converted verify service response to OpenId4VpRequest for client_id: {}", iarRequest.getClientId());
        log.debug("OpenId4VpRequest - responseType: {}, responseMode: {}, responseUri: {}, nonce: {}", 
                  openId4VpRequest.get("response_type"), openId4VpRequest.get("response_mode"), 
                  openId4VpRequest.get("response_uri"), openId4VpRequest.get("nonce"));

        return openId4VpRequest;
    }

    private void validateConfiguration() {
        if (!StringUtils.hasText(verifyServiceVpRequestEndpoint)) {
            throw new IllegalStateException("mosip.certify.verify.service.vp-request-endpoint must be configured");
        }
        if (!StringUtils.hasText(verifierClientId)) {
            throw new IllegalStateException("mosip.certify.verify.service.verifier-client-id must be configured");
        }
        if (!StringUtils.hasText(certifyIarEndpoint)) {
            throw new IllegalStateException("mosip.certify.oauth.interactive-authorization-endpoint must be configured");
        }
        log.info("IarVpRequestService configuration validation successful");
    }
}

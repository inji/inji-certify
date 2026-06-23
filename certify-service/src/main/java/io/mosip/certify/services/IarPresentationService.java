/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.fasterxml.jackson.databind.JsonNode;
import io.inji.verify.dto.result.VCResultDto;
import io.inji.verify.dto.submission.VPTokenResultDto;
import io.inji.verify.enums.VPResultStatus;
import io.inji.verify.services.VerifiablePresentationRequestService;
import io.inji.verify.services.VerifiablePresentationSubmissionService;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.IarStatus;
import io.mosip.certify.core.dto.IarAuthorizationRequest;
import io.mosip.certify.core.dto.IarAuthorizationResponse;
import io.mosip.certify.core.dto.VpVerificationResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.repository.IarSessionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

import java.time.LocalDateTime;
import java.util.*;

/**
 * Service for handling VP Presentation processing using the embedded inji-verify library.
 */
@Slf4j
@Service
public class IarPresentationService {

    private final IarSessionRepository iarSessionRepository;

    private final ObjectMapper objectMapper;

    private final VerifiablePresentationSubmissionService vpSubmissionService;

    private final VerifiablePresentationRequestService vpRequestService;

    @Value("${mosip.certify.iar.authorization-code.length:24}")
    private int authorizationCodeLength;

    @Value("#{'${mosip.certify.iar.identity-data:uin,vid,UIN,UID}'.split(',')}")
    private Set<String> identityKeys;

    @Autowired
    public IarPresentationService(IarSessionRepository iarSessionRepository,
                                   ObjectMapper objectMapper,
                                   VerifiablePresentationSubmissionService vpSubmissionService,
                                   VerifiablePresentationRequestService vpRequestService) {
        this.iarSessionRepository = iarSessionRepository;
        this.objectMapper = objectMapper;
        this.vpSubmissionService = vpSubmissionService;
        this.vpRequestService = vpRequestService;
    }

    /**
     * Process VP presentation and return authorization response
     */
    public IarAuthorizationResponse processVpPresentation(IarAuthorizationRequest presentationRequest) throws CertifyException {
        log.info("Processing VP presentation for auth_session: {}", presentationRequest.getAuthSession());

        try {
            Optional<IarSession> sessionOpt = iarSessionRepository.findByAuthSession(presentationRequest.getAuthSession());
            if (sessionOpt.isEmpty()) {
                log.warn("Invalid auth_session: {}", presentationRequest.getAuthSession());
                throw new CertifyException(ErrorConstants.INVALID_REQUEST, "Invalid auth_session");
            }
            IarSession session = sessionOpt.get();

            submitVpToVerifier(session.getResponseUri(),
                             presentationRequest.getOpenid4vpPresentation(),
                             session.getRequestId(),
                             session.getTransactionId());

            VpVerificationResponse verificationResponse = getVpVerificationResult(session.getTransactionId());

            IarAuthorizationResponse response = new IarAuthorizationResponse();
            if (IarStatus.OK.getValue().equals(verificationResponse.getStatus())) {
                String identity = extractIdentity(verificationResponse);

                if (identity == null || identity.isEmpty()) {
                    throw new CertifyException("invalid_vp", "VP does not contain identity attributes (UIN/VID)");
                }

                session.setIdentityData(identity);
                iarSessionRepository.save(session);
                String authorizationCode = generateAndStoreAuthorizationCode(session);
                response.setStatus(IarStatus.OK);
                response.setCode(authorizationCode);
                log.info("Authorization code generated after successful VP cryptographic verification for auth_session: {}, request_id: {}",
                         presentationRequest.getAuthSession(), session.getRequestId());
            } else {
                response.setStatus(IarStatus.ERROR);
                log.warn("Authorization denied - VP cryptographic verification failed for auth_session: {}, request_id: {}, error: {}",
                         presentationRequest.getAuthSession(), session.getRequestId(),
                         verificationResponse.getError());
            }

            return response;

        } catch (CertifyException e) {
            log.error("VP presentation processing failed for auth_session: {}, error: {}",
                      presentationRequest.getAuthSession(), e.getErrorCode(), e);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during VP presentation processing for auth_session: {}",
                      presentationRequest.getAuthSession(), e);
            throw new CertifyException("unknown_error", "VP presentation processing failed", e);
        }
    }

    /**
     * Submit VP presentation to the embedded inji-verify library.
     * responseUri is retained in the signature for session compatibility but is not used for HTTP.
     */
    private void submitVpToVerifier(String responseUri, String vpPresentationJson, String requestId, String transactionId) throws CertifyException {
        log.info("Submitting VP to vpSubmissionService with state(requestId)={}, transactionId={}",
                requestId, transactionId);

        try {
            Map<String, Object> vpPresentationData = objectMapper.readValue(vpPresentationJson, new TypeReference<Map<String, Object>>() {});

            Object vpTokenObj = vpPresentationData.get("vp_token");
            if (vpTokenObj == null) {
                log.error("Missing vp_token in wallet's VP presentation");
                throw new CertifyException("vp_submission_failed", "Missing vp_token in VP presentation");
            }

            Object presentationSubmissionObj = vpPresentationData.get("presentation_submission");
            if (presentationSubmissionObj == null) {
                log.error("Missing presentation_submission in wallet's VP presentation");
                throw new CertifyException("vp_submission_failed", "Missing presentation_submission in VP presentation");
            }

            String vpTokenJson;
            if (vpTokenObj instanceof String vpTokenString) {
                vpTokenJson = vpTokenString;
                log.debug("vp_token is a JWT string");
            } else {
                vpTokenJson = objectMapper.writeValueAsString(vpTokenObj);
                log.debug("vp_token serialized to JSON, length: {}", vpTokenJson.length());
            }

            String presentationSubmissionJson;
            if (presentationSubmissionObj instanceof String presentationSubmissionString) {
                presentationSubmissionJson = presentationSubmissionString;
            } else {
                presentationSubmissionJson = objectMapper.writeValueAsString(presentationSubmissionObj);
                log.debug("presentation_submission serialized to JSON, length: {}", presentationSubmissionJson.length());
            }

            log.debug("Calling vpSubmissionService.submit with state(requestId): {}", requestId);
            ResponseEntity<?> submissionResponse = vpSubmissionService.submit(vpTokenJson, presentationSubmissionJson, requestId, null, null);

            if (submissionResponse.getStatusCode().is2xxSuccessful()) {
                log.info("VP submission accepted, status: {}", submissionResponse.getStatusCode());
            } else {
                log.warn("VP submission returned non-success status: {}", submissionResponse.getStatusCode());
                throw new CertifyException("vp_submission_failed",
                    "VP submission failed with status: " + submissionResponse.getStatusCode());
            }

        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to submit VP presentation, requestId: {}, transactionId: {}",
                     requestId, transactionId, e);
            throw new CertifyException("vp_submission_failed",
                "Failed to submit VP presentation: " + e.getMessage(), e);
        }
    }

    /**
     * Get VP verification result from the embedded inji-verify library.
     */
    private VpVerificationResponse getVpVerificationResult(String transactionId) throws CertifyException {
        try {
            List<String> requestIds = vpRequestService.getLatestRequestIdFor(transactionId);
            log.debug("Fetching VP result for transactionId: {}, requestIds: {}", transactionId, requestIds);

            VPTokenResultDto vpResult = vpSubmissionService.getVPResult(requestIds, transactionId);

            VpVerificationResponse response = new VpVerificationResponse();
            response.setRequestId(transactionId);

            if (vpResult != null) {
                Map<String, Object> verificationDetails = buildVerificationDetails(vpResult);
                response.setVerificationDetails(verificationDetails);

                if (VPResultStatus.SUCCESS == vpResult.getVpResultStatus()) {
                    response.setStatus(IarStatus.OK.getValue());
                    log.info("VP cryptographic verification successful for transaction_id: {}", transactionId);
                } else {
                    response.setStatus(IarStatus.ERROR.getValue());
                    response.setError("verification_failed");
                    response.setErrorDescription("VP cryptographic verification failed");
                    log.warn("VP cryptographic verification failed for transaction_id: {}, status: {}",
                             transactionId, vpResult.getVpResultStatus());
                }
            } else {
                response.setStatus(IarStatus.ERROR.getValue());
                response.setError("no_verification_result");
                response.setErrorDescription("No VP verification result available");
                log.error("No verification result available for transaction_id: {}", transactionId);
            }

            return response;

        } catch (Exception e) {
            log.error("Failed to get VP verification results for transaction_id: {}", transactionId, e);

            VpVerificationResponse errorResponse = new VpVerificationResponse();
            errorResponse.setStatus(IarStatus.ERROR.getValue());
            errorResponse.setRequestId(transactionId);
            errorResponse.setError("verification_result_error");
            errorResponse.setErrorDescription("Failed to retrieve verification results: " + e.getMessage());

            return errorResponse;
        }
    }

    private Map<String, Object> buildVerificationDetails(VPTokenResultDto vpResult) {
        Map<String, Object> details = new HashMap<>();
        details.put("vpResultStatus", vpResult.getVpResultStatus().name());
        List<Map<String, Object>> vcResultsList = new ArrayList<>();
        if (vpResult.getVcResults() != null) {
            for (VCResultDto vcResult : vpResult.getVcResults()) {
                Map<String, Object> vcEntry = new HashMap<>();
                vcEntry.put("vc", vcResult.getVc());
                vcResultsList.add(vcEntry);
            }
        }
        details.put("vcResults", vcResultsList);
        return details;
    }

    /**
     * Generate and store authorization code.
     */
    private String generateAndStoreAuthorizationCode(IarSession session) throws CertifyException {
        if (StringUtils.hasText(session.getAuthorizationCode())) {
            if (Boolean.TRUE.equals(session.getIsCodeUsed())) {
                log.error("Authorization code already used for auth_session: {}, cannot reuse", session.getAuthSession());
                throw new CertifyException("invalid_request",
                    "Authorization code for this session has already been used. Please start a new authorization flow.");
            }
            log.info("Authorization code already exists for auth_session: {}, returning existing code", session.getAuthSession());
            return session.getAuthorizationCode();
        }

        if (authorizationCodeLength < 24) {
            throw new CertifyException("invalid_configuration",
                "Authorization code length must be at least 24 characters. Current value: " + authorizationCodeLength);
        }

        int byteLength = (int) Math.ceil(authorizationCodeLength * 0.75);
        byte[] randomBytes = new byte[byteLength];
        new java.security.SecureRandom().nextBytes(randomBytes);
        String encoded = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        if (encoded.length() < authorizationCodeLength) {
            byte[] additionalBytes = new byte[16];
            new java.security.SecureRandom().nextBytes(additionalBytes);
            String additionalEncoded = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(additionalBytes);
            encoded = (encoded + additionalEncoded).substring(0, authorizationCodeLength);
        }

        String authCode = "iar_auth_" + encoded.substring(0, authorizationCodeLength);
        log.debug("Generated authorization code for auth_session: {} (length: {})", session.getAuthSession(), authCode.length());

        session.setAuthorizationCode(authCode);
        session.setCodeIssuedAt(LocalDateTime.now());
        iarSessionRepository.save(session);
        log.info("Authorization code stored for auth_session: {}", session.getAuthSession());

        return authCode;
    }

    private String extractIdentity(VpVerificationResponse verificationResponse) {
        Object detailsObj = verificationResponse.getVerificationDetails();
        if (!(detailsObj instanceof Map)) {
            return null;
        }

        Map<String, Object> details = (Map<String, Object>) detailsObj;
        Object vcResultsObj = details.get("vcResults");
        if (!(vcResultsObj instanceof List)) {
            return null;
        }

        List<Map<String, Object>> vcResults = (List<Map<String, Object>>) vcResultsObj;
        for (Map<String, Object> vcEntry : vcResults) {
            Object vcStringObj = vcEntry.get("vc");
            if (!(vcStringObj instanceof String)) {
                continue;
            }
            String extracted = extractIdentityFromVc((String) vcStringObj);
            if (extracted != null && !extracted.isEmpty()) {
                return extracted;
            }
        }
        return null;
    }

    private String extractIdentityFromVc(String vcJson) {
        try {
            JsonNode root = objectMapper.readTree(vcJson);
            JsonNode cs = root.path("credentialSubject");
            if (cs.isMissingNode()) {
                return null;
            }
            Iterator<Map.Entry<String, JsonNode>> fields = cs.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                if (identityKeys.contains(entry.getKey())) {
                    return entry.getValue().asText();
                }
            }
        } catch (Exception ex) {
            log.warn("Failed to parse VC JSON for identity extraction", ex);
        }
        return null;
    }
}

package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.util.CommonUtil;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.AccessTokenJwtUtil;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Valid;
import jakarta.validation.Validator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

@Service
@Slf4j
public class PreAuthorizedCodeService {

    @Autowired
    private VCICacheService vciCacheService;

    @Autowired
    private AccessTokenJwtUtil accessTokenJwtUtil;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

    @Autowired
    private Validator validator;

    @Value("${mosip.certify.identifier}")
    private String issuerIdentifier;

    @Value("${mosip.certify.pre-auth.default-expiry-seconds:600}")
    private int defaultExpirySeconds;

    @Value("${mosip.certify.pre-auth.min-expiry-seconds:60}")
    private int minExpirySeconds;

    @Value("${mosip.certify.pre-auth.max-expiry-seconds:86400}")
    private int maxExpirySeconds;

    @Value("${mosip.certify.credential-offer-url}")
    private String credentialOfferUrl;

    @Value("${mosip.certify.oauth.token.expires-in-seconds:600}")
    private int accessTokenExpirySeconds;

    @Value("${mosip.certify.cnonce-expire-seconds:300}")
    private int cNonceExpirySeconds;

    @Value("${mosip.certify.oauth.issuer}")
    private String oauthIssuer;

    @Value("${mosip.certify.oauth.access-token.audience}")
    private String oauthAudience;

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    public String generatePreAuthorizedCode(PreAuthorizedRequest request) {
        validatePreAuthorizedRequest(request);
        int expirySeconds = request.getExpiresIn() != null ? request.getExpiresIn() : defaultExpirySeconds;
        if (expirySeconds < minExpirySeconds || expirySeconds > maxExpirySeconds) {
            log.error("expires_in {} out of bounds [{}, {}]", expirySeconds, minExpirySeconds, maxExpirySeconds);
            throw new InvalidRequestException(ErrorConstants.INVALID_EXPIRY_RANGE);
        }

        String offerId = UUID.randomUUID().toString();
        String preAuthCode = generateUniquePreAuthCode();

        long currentTime = System.currentTimeMillis();
        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(request.getCredentialConfigurationId())
                .claims(request.getClaims())
                .txnCode(request.getTxCode())
                .createdAt(currentTime)
                .expiresAt(currentTime + (expirySeconds * 1000L)).build();

        vciCacheService.setPreAuthCodeData(preAuthCode, codeData);

        CredentialOfferResponse offerResponse = buildCredentialOffer(request.getCredentialConfigurationId(), preAuthCode, request.getTxCode());
        vciCacheService.setCredentialOffer(offerId, offerResponse);

        return buildCredentialOfferUri(offerId);
    }

    private void validatePreAuthorizedRequest(PreAuthorizedRequest request) {
        CredentialIssuerMetadataDTO metadata = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");
        Map<String, CredentialConfigurationSupportedDTO> supportedConfigs = metadata
                .getCredentialConfigurationSupportedDTO();

        if (supportedConfigs == null || !supportedConfigs.containsKey(request.getCredentialConfigurationId())) {
            log.error("Invalid credential configuration ID: {}", request.getCredentialConfigurationId());
            throw new InvalidRequestException(ErrorConstants.INVALID_CREDENTIAL_CONFIGURATION_ID);
        }

        CredentialConfigurationSupportedDTO config = supportedConfigs.get(request.getCredentialConfigurationId());
        validateClaims(config, request.getClaims());
    }

    private void validateClaims(CredentialConfigurationSupportedDTO config, Map<String, Object> providedClaims) {
        if (providedClaims == null) {
            providedClaims = Collections.emptyMap();
        }

        String format = config.getFormat();
        Set<String> allowedClaimKeys;

        if (VCFormats.LDP_VC.equals(format)) {
            // For ldp_vc: claims are defined in credential_definition.credentialSubject
            CredentialDefinition credDef = config.getCredentialDefinition();
            if (credDef != null && credDef.getCredentialSubject() != null) {
                allowedClaimKeys = credDef.getCredentialSubject().keySet();
            } else {
                return; // No claims defined, allow any
            }
            // For ldp_vc, just validate unknown claims (mandatory not supported in this structure)
            List<String> unknownClaims = new ArrayList<>();
            for (String providedClaim : providedClaims.keySet()) {
                if (!allowedClaimKeys.contains(providedClaim)) {
                    unknownClaims.add(providedClaim);
                }
            }
            if (!unknownClaims.isEmpty()) {
                log.error("Unknown claims provided: {}", unknownClaims);
                throw new InvalidRequestException(ErrorConstants.UNKNOWN_CLAIMS);
            }
        } else {
            // For mso_mdoc, vc+sd-jwt: use top-level claims with mandatory checking
            Map<String, Object> requiredClaims = config.getClaims();
            if (requiredClaims == null || requiredClaims.isEmpty()) {
                return;
            }
            validateClaimsWithMandatory(requiredClaims, providedClaims);
        }
    }

    private void validateClaimsWithMandatory(Map<String, Object> requiredClaims, Map<String, Object> providedClaims) {
        List<String> missingClaims = new ArrayList<>();
        List<String> unknownClaims = new ArrayList<>();

        for (Map.Entry<String, Object> entry : requiredClaims.entrySet()) {
            if (!(entry.getValue() instanceof Map)) {
                log.warn("Claim {} has unexpected format, skipping mandatory check", entry.getKey());
                continue;
            }
            Map<String, Object> claimAttrs = (Map<String, Object>) entry.getValue();
            Boolean mandatory = claimAttrs.containsKey(Constants.MANDATORY)
                    ? (Boolean) claimAttrs.get(Constants.MANDATORY)
                    : Boolean.FALSE;

            if (Boolean.TRUE.equals(mandatory)) {
                if (!providedClaims.containsKey(entry.getKey()) ||
                        providedClaims.get(entry.getKey()) == null) {
                    missingClaims.add(entry.getKey());
                }
            }
        }

        for (String providedClaim : providedClaims.keySet()) {
            if (!requiredClaims.containsKey(providedClaim)) {
                unknownClaims.add(providedClaim);
            }
        }

        if (!missingClaims.isEmpty()) {
            log.error("Missing mandatory claims: {}", missingClaims);
            throw new InvalidRequestException(ErrorConstants.MISSING_MANDATORY_CLAIM);
        }

        if (!unknownClaims.isEmpty()) {
            log.error("Unknown claims provided: {}", unknownClaims);
            throw new InvalidRequestException(ErrorConstants.UNKNOWN_CLAIMS);
        }
    }

    public CredentialOfferResponse getCredentialOffer(String offerId) {
        log.info("Retrieving credential offer for ID: {}", offerId);

        // Trim offerId early to ensure validation and cache lookup use the same value
        if (offerId != null) {
            offerId = offerId.trim();
        }

        if (!isValidUUID(offerId)) {
            log.error("Invalid offer_id format: {}", offerId);
            throw new InvalidRequestException(ErrorConstants.INVALID_OFFER_ID_FORMAT);
        }

        CredentialOfferResponse offer = vciCacheService.getCredentialOffer(offerId);

        if (offer == null) {
            log.error("Credential offer not found or expired for ID: {}", offerId);
            throw new CertifyException(ErrorConstants.CREDENTIAL_OFFER_NOT_FOUND, "Credential offer not found or expired");
        }

        log.info("Successfully retrieved credential offer for ID: {}", offerId);
        return offer;
    }

    private boolean isValidUUID(String str) {
        if (str == null || str.trim().isEmpty()) {
            return false;
        }
        try {
            UUID.fromString(str.trim());
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private String generateUniquePreAuthCode() {
        String preAuthCode;
        int attempts = 0;
        final int MAX_ATTEMPTS = 3;

        do {
            preAuthCode = generateSecureCode(32);
            attempts++;
            if (vciCacheService.getPreAuthCodeData(preAuthCode) == null) {
                return preAuthCode;
            }
        } while (attempts < MAX_ATTEMPTS);

        throw new IllegalStateException(
                "Failed to generate unique pre-authorized code after " + MAX_ATTEMPTS + " attempts");
    }

    private CredentialOfferResponse buildCredentialOffer(String configId, String preAuthCode, String txnCode) {
        Grant.PreAuthorizedCodeGrantType grant = Grant.PreAuthorizedCodeGrantType.builder()
                .preAuthorizedCode(preAuthCode)
                .txCode(StringUtils.hasText(txnCode) ? buildTxCodeInfo(txnCode) : null).build();

        Grant grants = Grant.builder().preAuthorizedCode(grant).build();

        return CredentialOfferResponse.builder()
                .credentialIssuer(issuerIdentifier)
                .credentialConfigurationIds(Collections.singletonList(configId))
                .grants(grants)
                .build();
    }

    private TxCode buildTxCodeInfo(String txnCode) {
        return TxCode.builder()
                .length(txnCode.length())
                .inputMode(txnCode.matches("\\d+") ? "numeric" : "text")
                .description("Please enter the transaction code provided to you")
                .build();
    }

    private String buildCredentialOfferUri(String offerId) {
        String offerFetchUrl = credentialOfferUrl + offerId;
        try {
            String encodedUrl = URLEncoder.encode(offerFetchUrl, StandardCharsets.UTF_8.name());
            return "openid-credential-offer://?credential_offer_uri=" + encodedUrl;
        } catch (java.io.UnsupportedEncodingException e) {
            // UTF-8 is always supported, this should never happen
            throw new RuntimeException("UTF-8 encoding not supported", e);
        }
    }

    private String generateSecureCode(int length) {
        StringBuilder code = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            code.append(ALPHANUMERIC.charAt(secureRandom.nextInt(ALPHANUMERIC.length())));
        }
        return code.toString();
    }

    /**
     * Exchange pre-authorized code for access token
     */
    public OAuthTokenResponse exchangePreAuthorizedCode(OAuthTokenRequest request) {
        Set<ConstraintViolation<OAuthTokenRequest>> violations =
                validator.validate(request);

        if (!violations.isEmpty()) {
            throw new ConstraintViolationException(violations);
        }

        log.info("Processing token request for grant_type: {}", request.getGrant_type());

        // Retrieve and validate pre-auth code data
        PreAuthCodeData codeData = vciCacheService.getPreAuthCodeData(request.getPre_authorized_code());

        validateTokenRequest(request, codeData);

        // Generate c_nonce
        String cNonce = accessTokenJwtUtil.generateCNonce();
        // Generate access token
        String accessToken = generateAccessToken(codeData, cNonce);

        long currentTime = System.currentTimeMillis();
        PreAuthTransaction transaction = PreAuthTransaction.builder()
                .credentialConfigurationId(codeData.getCredentialConfigurationId())
                .claims(codeData.getClaims())
                .cNonce(cNonce)
                .cNonceIssuedEpoch(java.time.LocalDateTime.now(java.time.ZoneOffset.UTC).toEpochSecond(java.time.ZoneOffset.UTC))
                .cNonceExpireSeconds(cNonceExpirySeconds)
                .createdAt(currentTime)
                .build();

        vciCacheService.setVCITransaction(CommonUtil.generateOIDCAtHash(accessToken), transaction);

        log.info("Successfully exchanged pre-authorized code for access token");

        OAuthTokenResponse response = new OAuthTokenResponse();
        response.setAccessToken(accessToken);
        response.setTokenType("Bearer");
        response.setExpiresIn(accessTokenExpirySeconds);
        response.setCNonce(cNonce);
        response.setCNonceExpiresIn(cNonceExpirySeconds);
        return response;
    }

    private void validateTokenRequest(OAuthTokenRequest request, PreAuthCodeData codeData) {

        // Validate grant type
        if (!Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE.equals(request.getGrant_type())) {
            log.error("Unsupported grant type: {}", request.getGrant_type());
            throw new CertifyException(ErrorConstants.UNSUPPORTED_GRANT_TYPE, "Grant type not supported");
        }

        // Atomically claim the pre-authorized code
        boolean claimed = vciCacheService.claimPreAuthCode(request.getPre_authorized_code());
        if (!claimed) {
            log.error("Pre-authorized code already used or invalid");
            throw new CertifyException(ErrorConstants.INVALID_GRANT, "Pre-authorized code has already been used  or invalid");
        }

        // Check expiry
        long currentTime = System.currentTimeMillis();
        if (codeData.getExpiresAt() < currentTime) {
            log.error("Pre-authorized code expired. Expiry: {}, Current: {}", codeData.getExpiresAt(), currentTime);
            throw new CertifyException("pre_auth_code_expired", "Pre-authorized code has expired");
        }

        // Validate transaction code if required
        String expectedTxCode = codeData.getTxnCode();
        if (StringUtils.hasText(expectedTxCode) && !StringUtils.hasText(request.getTx_code())) {
            log.error("Transaction code required but not provided");
            throw new CertifyException("tx_code_required", "Transaction code is required for this pre-authorized code");
        }
        if (StringUtils.hasText(expectedTxCode) && !expectedTxCode.equals(request.getTx_code())) {
            log.error("Transaction code mismatch");
            throw new CertifyException("tx_code_mismatch", "Transaction code does not match");
        }
    }

    /**
     * Generate a signed JWT access token for pre-authorized code flow.
     * Calls AccessTokenJwtUtil.generateSignedJwt directly with raw parameters.
     */
    private String generateAccessToken(PreAuthCodeData codeData, String cNonce) {
        try {
            String claimsJson = objectMapper.writeValueAsString(codeData.getClaims());
            String credentialConfigId = codeData.getCredentialConfigurationId();

            // Lookup credential configuration in database
            String credentialScope = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigId)
                    .map(credentialConfig -> {
                        if (!Constants.ACTIVE.equals(credentialConfig.getStatus())) {
                            log.error("Credential configuration is not active for ID: {}, status: {}",
                                    credentialConfigId, credentialConfig.getStatus());
                            throw new CertifyException("invalid_request",
                                    "Credential configuration is not active: " + credentialConfigId);
                        }
                        String scope = credentialConfig.getScope();
                        if (!StringUtils.hasText(scope)) {
                            log.error("Scope is not configured for credential configuration ID: {}", credentialConfigId);
                            throw new CertifyException("server_error",
                                    "Scope not configured for credential: " + credentialConfigId);
                        }
                        return scope;
                    })
                    .orElseThrow(() -> {
                        log.error("Credential configuration not found for ID: {}", credentialConfigId);
                        return new CertifyException("invalid_request",
                                "Invalid credential_configuration_id: " + credentialConfigId);
                    });

            return accessTokenJwtUtil.generateSignedJwt(
                    claimsJson,
                    credentialScope,
                    "",
                    oauthIssuer,
                    oauthAudience,
                    accessTokenExpirySeconds,
                    cNonce
            );
        } catch (Exception e) {
            log.error("Failed to generate access token for pre-authorized code flow", e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Failed to generate access token", e);
        }
    }
}
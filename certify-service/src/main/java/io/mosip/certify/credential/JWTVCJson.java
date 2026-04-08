/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.credential;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDtoV2;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JWTVCJson extends Credential {

    private static final Set<String> DEFAULT_ALLOWED_ALGS =
            Set.of("ES256", "RS256", "PS256", "EdDSA");

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${mosip.certify.credential-config.jwt-vc.fallback-expiry-seconds:31536000}")
    private long fallbackExpirySeconds; // configurable fallback expiry

    @Autowired
    public JWTVCJson(VCFormatter vcFormatter, SignatureService signatureService) {
        super(vcFormatter, signatureService);
    }

    @Override
    public boolean canHandle(String format) {
        return "jwt_vc_json".equals(format) || VCFormats.JWT_VC_JSON.equals(format);
    }

    @Override
    public String createCredential(Map<String, Object> updatedTemplateParams, String templateName) {
        return super.createCredential(updatedTemplateParams, templateName);
    }

    public VCResult<?> addProof(Map<String, Object> vcToSign,
                               Map<String, Object> headers,
                               String signAlgorithm,
                               String appID,
                               String refID,
                               String didUrl,
                               String signatureCryptoSuite) {

        VCResult<String> vcResult = new VCResult<>();

        try {
            // Convert VC Map → JSON → Map (normalized)
            String vcJsonString = objectMapper.writeValueAsString(vcToSign);
            JsonNode vcNode = objectMapper.readTree(vcJsonString);
            @SuppressWarnings("unchecked")
            Map<String, Object> vcMap = objectMapper.convertValue(vcNode, Map.class);

            // Validate structure
            validateVcStructure(vcMap);

            long now = Instant.now().getEpochSecond();

            Map<String, Object> claims = new LinkedHashMap<>();
            Object issuer = vcMap.get("issuer");
            if (issuer instanceof Map<?, ?> map) {
                Object id = map.get("id");
                claims.put("iss", id != null ? id.toString() : didUrl);
            } else if (issuer != null) {
                claims.put("iss", issuer.toString());
            } else {
                claims.put("iss", didUrl);
            }
            claims.put("jti", "urn:uuid:" + UUID.randomUUID());

            // issuanceDate / validFrom → iat/nbf
            Object issuanceDateObj = vcMap.get("issuanceDate");
            if (issuanceDateObj == null) {
                issuanceDateObj = vcMap.get("validFrom");
            }
            if (issuanceDateObj instanceof String) {
                try {
                    Instant issuanceInstant = Instant.parse((String) issuanceDateObj);
                    claims.put("iat", issuanceInstant.getEpochSecond());
                    claims.put("nbf", issuanceInstant.getEpochSecond());
                } catch (Exception ex) {
                    log.warn("Invalid issuanceDate/validFrom format; fallback to now", ex);
                    claims.put("iat", now);
                    claims.put("nbf", now);
                }
            } else {
                claims.put("iat", now);
                claims.put("nbf", now);
            }

            // expirationDate / validUntil → exp
            Object expObj = vcMap.get("expirationDate");
            if (expObj == null) {
                expObj = vcMap.get("validUntil");
            }
            if (expObj instanceof String) {
                try {
                    Instant expInstant = Instant.parse((String) expObj);
                    claims.put("exp", expInstant.getEpochSecond());
                } catch (Exception ex) {
                    log.warn("Invalid expirationDate/validUntil format; fallback expiry used", ex);
                    claims.put("exp", now + fallbackExpirySeconds);
                }
            } else {
                claims.put("exp", now + fallbackExpirySeconds);
            }

            // sub extraction
            Object credentialSubjectObj = vcMap.get("credentialSubject");
            if (credentialSubjectObj instanceof Map<?, ?> map) {
                Object sid = map.get("id");
                if (sid != null) claims.put("sub", sid);
            } else if (credentialSubjectObj instanceof List<?> list) {
                if (!list.isEmpty() && list.get(0) instanceof Map<?, ?> map) {
                    Object sid = map.get("id");
                    if (sid != null) claims.put("sub", sid);
                }
            }

            // embed VC
            claims.put("vc", vcMap);
            if (!claims.containsKey("sub")) {
    claims.put("sub", didUrl);
}

            // Algorithm validation
            if (signAlgorithm == null || !isAlgAllowed(signAlgorithm)) {
                log.error("Unsupported signing algorithm {}", signAlgorithm);
                throw new CertifyException(VCIErrorConstants.INVALID_PROOF,
                        "Unsupported signing algorithm");
            }

            // Headers
            Map<String, Object> additionalHeaders = new LinkedHashMap<>();
            if (headers != null) {
                additionalHeaders.putAll(headers);
            }
            additionalHeaders.put("alg", signAlgorithm);
            additionalHeaders.put("typ", "JWT");
            additionalHeaders.put("kid", refID);

            Map<String, String> additionalHeadersStr = additionalHeaders.entrySet()
                    .stream()
                    .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            e -> e.getValue() == null ? "" : String.valueOf(e.getValue()),
                            (a, b) -> b,
                            LinkedHashMap::new
                    ));

            // Signing payload
            JWSSignatureRequestDtoV2 payload = new JWSSignatureRequestDtoV2();
            payload.setDataToSign(objectMapper.writeValueAsString(claims));
            payload.setApplicationId(appID);
            payload.setReferenceId(refID);
            payload.setAdditionalHeaders(additionalHeadersStr);
            payload.setSignAlgorithm(signAlgorithm);
            payload.setIncludePayload(true);
            payload.setIncludeCertificateChain(true);
            payload.setIncludeCertHash(true);
            payload.setValidateJson(false);
            payload.setB64JWSHeaderParam(true);
            payload.setCertificateUrl("");

            JWTSignatureResponseDto jwsSignedData = signatureService.jwsSignV2(payload);

            vcResult.setCredential(jwsSignedData.getJwtSignedData());
            vcResult.setFormat(VCFormats.JWT_VC_JSON);

            return vcResult;

        } catch (JsonProcessingException e) {
            log.error("JSON processing error while creating JWT VC", e);
            throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR,
                    "Failed to process VC JSON", e);
        } catch (CertifyException ce) {
            throw ce;
        } catch (Exception ex) {
            log.error("Signing error while creating JWT VC", ex);
            throw new CertifyException(ErrorConstants.VC_SIGNING_ERROR,
            "JWT VC signing failed", ex);
        }
    }

    private void validateVcStructure(Map<String, Object> vcMap) {
        if (vcMap == null) {
            throw new CertifyException(VCIErrorConstants.INVALID_CREDENTIAL_REQUEST,
                    "VC is null");
        }
        if (!vcMap.containsKey("@context")
                || !vcMap.containsKey("type")
                || !vcMap.containsKey("credentialSubject")) {
            throw new CertifyException(VCIErrorConstants.INVALID_CREDENTIAL_REQUEST,
                    "VC missing required JSON-LD fields: @context/type/credentialSubject");
        }
    }

    private boolean isAlgAllowed(String alg) {
        return DEFAULT_ALLOWED_ALGS.contains(alg);
    }
}
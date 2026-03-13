package io.mosip.certify.credential;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class W3CJwtJson extends Credential {

    private final ObjectMapper mapper = new ObjectMapper();

    public W3CJwtJson(VCFormatter vcFormatter,
        SignatureService signatureService) {
        super(vcFormatter, signatureService);
    }

    @Override
    public boolean canHandle(String format) {
        return VCFormats.JWT_VC_JSON.equalsIgnoreCase(format);
    }

    @Override
    public VCResult<?> addProof(
            String vcToSign,
            String headers,
            String signAlgorithm,
            String appID,
            String refID,
            String didUrl,
            String signatureCryptoSuite) {

        try {

            Map<String, Object> vcMap =
                    mapper.readValue(vcToSign,
                    new TypeReference<Map<String, Object>>() {});
            long now = Instant.now().getEpochSecond();

            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("iss", didUrl);
            claims.put("iat", now);
            claims.put("nbf", now);
            claims.put("exp", now + 31536000);
            claims.put("jti", "urn:uuid:" + UUID.randomUUID());
            claims.put("vc", vcMap);

            Object credentialSubjectObj = vcMap.get("credentialSubject");

            if (credentialSubjectObj instanceof Map<?, ?> credentialSubject) {
                Object subjectId = credentialSubject.get("id");
                if (subjectId != null) {
                    claims.put("sub", subjectId);
                }
            }
            JWSSignatureRequestDto jwsRequest = new JWSSignatureRequestDto();
            jwsRequest.setDataToSign(mapper.writeValueAsString(claims));
            jwsRequest.setApplicationId(appID);
            jwsRequest.setReferenceId(refID);
            jwsRequest.setIncludePayload(false);
            jwsRequest.setIncludeCertificate(false);
            jwsRequest.setIncludeCertHash(true);
            jwsRequest.setValidateJson(false);
            jwsRequest.setB64JWSHeaderParam(false);
            jwsRequest.setCertificateUrl(didUrl);
            jwsRequest.setSignAlgorithm(signAlgorithm);

            JWTSignatureResponseDto response =
                    signatureService.jwsSign(jwsRequest);

            VCResult<String> vcResult = new VCResult<>();
            vcResult.setCredential(response.getJwtSignedData());
            vcResult.setFormat(VCFormats.JWT_VC_JSON);

            log.info("JWT VC signed successfully");

            return vcResult;

        } catch (Exception e) {
            log.error("Error signing JWT VC", e);
            throw new RuntimeException("JWT_VC_SIGNING_FAILED", e);
        }
    }
}
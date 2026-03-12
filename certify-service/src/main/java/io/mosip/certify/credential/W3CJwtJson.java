package io.mosip.certify.credential;

import java.time.Instant;
import java.util.*;
import java.util.Base64;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.dto.CertificateResponseDTO;
import io.mosip.certify.utils.DIDDocumentUtil;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.service.SignatureService;
import io.mosip.kernel.signature.dto.SignRequestDto;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class W3CJwtJson extends Credential {

    private final DIDDocumentUtil didDocumentUtil;
    private final ObjectMapper mapper = new ObjectMapper();

    public W3CJwtJson(VCFormatter vcFormatter,
                      SignatureService signatureService,
                      DIDDocumentUtil didDocumentUtil) {
        super(vcFormatter, signatureService);
        this.didDocumentUtil = didDocumentUtil;
    }

    @Override
    public boolean canHandle(String format) {
        return "jwt_vc_json".equalsIgnoreCase(format);
    }

    @Override
    public VCResult<?> addProof(String vcToSign,
                                String holderId,
                                String signAlgorithm,
                                String appID,
                                String refID,
                                String didUrl,
                                String signatureSuite) {

        try {

            // 1️⃣ Parse VC JSON
            Map<String, Object> vcMap =
                    mapper.readValue(vcToSign,
                    new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});

            // 2️⃣ Build JWT Claims
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("iss", didUrl); // issuer DID
            claims.put("sub", holderId);
            claims.put("iat", Instant.now().getEpochSecond());
            claims.put("nbf", Instant.now().getEpochSecond());
            claims.put("jti", "urn:uuid:" + UUID.randomUUID());
            claims.put("vc", vcMap);

            // 3️⃣ Get certificate details
            CertificateResponseDTO certificate =
                    didDocumentUtil.getCertificateDataResponseDto(appID, refID);

            // 4️⃣ Build JWT Header
            Map<String, Object> header = new LinkedHashMap<>();
            header.put("alg", signAlgorithm);
            header.put("typ", "JWT");

            // DID key reference
            header.put("kid", didUrl + "#" + certificate.getKeyId());

            // 5️⃣ Encode header and payload
            String encodedHeader = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(mapper.writeValueAsBytes(header));

            String encodedPayload = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(mapper.writeValueAsBytes(claims));

            String signingInput = encodedHeader + "." + encodedPayload;

            // 6️⃣ Sign using MOSIP Kernel
            SignRequestDto signRequest = new SignRequestDto();
            signRequest.setData(signingInput);

            Object signResponse = signatureService.sign(signRequest);

            String signature;

            if (signResponse instanceof byte[]) {
                signature = Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString((byte[]) signResponse);
            } else {
                signature = signResponse.toString();
            }

            // 7️⃣ Create compact JWT
            String compactJwt = signingInput + "." + signature;

            VCResult<String> vcResult = new VCResult<>();
            vcResult.setCredential(compactJwt);
            vcResult.setFormat("jwt_vc_json");

            log.info("JWT VC signed successfully");

            return vcResult;

        } catch (Exception e) {
            log.error("Error signing JWT VC", e);
            throw new RuntimeException("JWT_VC_SIGNING_FAILED", e);
        }
    }
}
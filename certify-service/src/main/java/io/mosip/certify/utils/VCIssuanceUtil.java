package io.mosip.certify.utils;

import com.nimbusds.jwt.SignedJWT;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.core.constants.*;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.exception.InvalidNonceException;
import io.mosip.certify.services.NonceCacheService;
import io.mosip.certify.api.dto.VCResult;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

public class VCIssuanceUtil {

    private VCIssuanceUtil() {
        // Private constructor to prevent instantiation
    }

    public static String validateAndGetClientNonce(NonceCacheService nonceCacheService,
                                                   String proof, Logger log) {
        String proofJwtNonce = null;
        boolean proofJwtHasNonceClaim = false;
        try {
            SignedJWT proofJwt = SignedJWT.parse(proof);
            Map<String, Object> proofClaims = proofJwt.getJWTClaimsSet().getClaims();
            proofJwtHasNonceClaim = proofClaims.containsKey("nonce");
            if (proofJwtHasNonceClaim) {
                proofJwtNonce = proofJwt.getJWTClaimsSet().getStringClaim("nonce");
                if (StringUtils.isBlank(proofJwtNonce)) {
                    log.error("Nonce claim is present in proof JWT but is blank");
                    throw new CertifyException(VCIErrorConstants.INVALID_PROOF, "Nonce claim must not be empty.");
                }
            }
        }
        catch (ParseException e) {
            // check iff specific error exists for invalid holderKey
            throw new CertifyException(VCIErrorConstants.INVALID_PROOF, "None of the submitted proofs passed validation.");
        }

        if (!proofJwtHasNonceClaim) {
            return null;
        }

        VCIssuanceTransaction transaction = nonceCacheService.getNonceTransaction(proofJwtNonce);

        int cNonceExpire;

        if (transaction == null) {
            log.error("Nonce Transaction could not be found");
            throw new CertifyException(NonceErrorConstants.INVALID_NONCE, "Nonce Transaction could not be found.");
        } else {
            cNonceExpire = transaction.getCNonceExpireSeconds();
        }

        String cachedNonce = transaction.getCNonce();

        long issuedEpoch = transaction.getCNonceIssuedEpoch();

        boolean nonceExpired = (cNonceExpire <= 0 ||
                (issuedEpoch + cNonceExpire) < LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));

        if (nonceExpired) {
            throw new CertifyException(NonceErrorConstants.NONCE_EXPIRED, "c_nonce is expired.");
        }

        return transaction.getCNonce();
    }

    @SuppressWarnings("unchecked")
    public static CredentialResponse<?> getCredentialResponse(String format, List<VCResult<?>> vcResults) {
        switch (format) {
            case VCFormats.LDP_VC:
                CredentialResponse<JsonLDObject> ldpVcResponse = new CredentialResponse<>();
                List<CredentialWrapper<JsonLDObject>> ldpVcCredentials = new ArrayList<>();
                for (VCResult<?> vcResult : vcResults) {
                    CredentialWrapper<JsonLDObject> credentialWrapper = new CredentialWrapper<>();
                    credentialWrapper.setCredential((JsonLDObject) vcResult.getCredential());
                    ldpVcCredentials.add(credentialWrapper);
                }
                ldpVcResponse.setCredentials(ldpVcCredentials);
                return ldpVcResponse;

            case VCFormats.VC_SD_JWT:
            case VCFormats.JWT_VC_JSON:
            case VCFormats.JWT_VC_JSON_LD:
            case VCFormats.MSO_MDOC:
                CredentialResponse<String> stringResponse = new CredentialResponse<>();
                List<CredentialWrapper<String>> mDocCredentials = new ArrayList<>();
                for (VCResult<?> vcResult : vcResults) {
                    CredentialWrapper<String> credentialWrapper = new CredentialWrapper<>();
                    credentialWrapper.setCredential((String) vcResult.getCredential());
                    mDocCredentials.add(credentialWrapper);
                }
                stringResponse.setCredentials(mDocCredentials);
                return stringResponse;

            default:
                throw new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT, " Input format " + format);
        }
    }

    public static Optional<CredentialMetadata> getScopeCredentialMapping(
            String scope,
            String credentialConfigId,
            CredentialIssuerMetadataDTO credentialIssuerMetadataDTO) {

        Map<String, CredentialConfigurationSupportedDTO> supportedCredentials =
                credentialIssuerMetadataDTO.getCredentialConfigurationSupportedDTO();

        Optional<CredentialConfigurationSupportedDTO> dtoOpt =
                Optional.ofNullable(supportedCredentials.get(credentialConfigId));

        if(dtoOpt.isEmpty()){
            throw new CertifyException(VCIErrorConstants.INVALID_CREDENTIAL_REQUEST,
                    "No credential configuration found for credential_configuration_id");
        }

        CredentialConfigurationSupportedDTO dto = dtoOpt.get();

        if(!Objects.equals(scope, dto.getScope())){
            return Optional.empty();
        }

        CredentialMetadata credentialMetadata = new CredentialMetadata();
        credentialMetadata.setFormat(dto.getFormat());
        credentialMetadata.setScope(dto.getScope());
        credentialMetadata.setId(credentialConfigId);
        credentialMetadata.setProofTypesSupported(dto.getProofTypesSupported());
        credentialMetadata.setType(dto.getCredentialDefinition().getType());
        credentialMetadata.setContext(dto.getCredentialDefinition().getContext());
        credentialMetadata.setCredentialSubject(dto.getCredentialDefinition().getCredentialSubject());
        credentialMetadata.setClaims(dto.getClaims());

       if(dto.getFormat().equals(VCFormats.VC_SD_JWT)) {
           credentialMetadata.setVct(dto.getVct());
       } else if(dto.getFormat().equals(VCFormats.MSO_MDOC)) {
           credentialMetadata.setDocType(dto.getDocType());
       }


       return Optional.of(credentialMetadata);
    }
}
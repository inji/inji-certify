package io.mosip.certify.utils;

import com.nimbusds.jwt.SignedJWT;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.api.util.AuditHelper;
import io.mosip.certify.core.constants.*;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.exception.InvalidNonceException;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.services.NonceCacheService;
import io.mosip.certify.api.dto.VCResult;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class VCIssuanceUtil {

    private VCIssuanceUtil() {
        // Private constructor to prevent instantiation
    }

    public static String validateAndGetClientNonce(NonceCacheService nonceCacheService,
                                                   String proof, Logger log, String nonceEndpoint) {
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
            throw new CertifyException(VCIErrorConstants.INVALID_PROOF, "Error encountered during proof jwt parsing.");
        }

        boolean hasNonceEndpoint = nonceEndpoint != null && !nonceEndpoint.isEmpty();

        if (proofJwtHasNonceClaim != hasNonceEndpoint) {
            if (proofJwtHasNonceClaim) {
                throw new CertifyException(
                        VCIErrorConstants.INVALID_PROOF,
                        "nonce claim is present, but issuer doesn't support nonce"
                );
            } else {
                throw new CertifyException(
                        VCIErrorConstants.INVALID_PROOF,
                        "nonce claim is missing, but issuer support nonce"
                );
            }
        }

        if (!proofJwtHasNonceClaim) {
            return null;
        }

        VCIssuanceTransaction transaction = nonceCacheService.getNonceTransaction(proofJwtNonce);

        int cNonceExpire;

        if (transaction == null) {
            log.error("Nonce Transaction could not be found");
            throw new CertifyException(NonceErrorConstants.INVALID_NONCE, "c_nonce is invalid or expired");
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
                List<CredentialResponse.CredentialWrapper<JsonLDObject>> ldpVcCredentials = new ArrayList<>();
                for (VCResult<?> vcResult : vcResults) {
                    CredentialResponse.CredentialWrapper<JsonLDObject> credentialWrapper = new CredentialResponse.CredentialWrapper<>();
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
                List<CredentialResponse.CredentialWrapper<String>> credentials = new ArrayList<>();
                for (VCResult<?> vcResult : vcResults) {
                    CredentialResponse.CredentialWrapper<String> credentialWrapper = new CredentialResponse.CredentialWrapper<>();
                    credentialWrapper.setCredential((String) vcResult.getCredential());
                    credentials.add(credentialWrapper);
                }
                stringResponse.setCredentials(credentials);
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

        CredentialConfigurationSupportedDTO credentialConfig = supportedCredentials.get(credentialConfigId);
        if(credentialConfig == null) {
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

    public static List<String> validateProofsAndGetHolderIds(
            CredentialRequest credentialRequest,
            CredentialMetadata credentialMetadata,
            String clientId,
            String accessTokenHash,
            AuditPlugin auditWrapper,
            ProofValidatorFactory proofValidatorFactory,
            NonceCacheService nonceCacheService,
            CredentialConfigurationService credentialConfigurationService) {
        Map<String, Object> supportedProofTypes = credentialMetadata.getProofTypesSupported();
        Map<String, Set<String>> proofs = credentialRequest.getProofs()
                .entrySet()
                .stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue() == null
                                ? Collections.emptySet()
                                : new HashSet<>(entry.getValue())
                ));
        List<String> holderIds = new ArrayList<>();
        String nonceEndpoint = credentialConfigurationService.fetchCredentialIssuerMetadata().getNonceEndpoint();
        for (Map.Entry<String,Set<String>> entry : proofs.entrySet()) {
            String proofType = entry.getKey();
            ProofValidator proofValidator = proofValidatorFactory.getProofValidator(proofType);
            if (proofValidator == null) {
                throw new CertifyException(ErrorConstants.UNSUPPORTED_PROOF_TYPE, "Unsupported proof type: " + proofType);
            }
            for (String proofValue : entry.getValue()) {
                try {
                    String validCNonce = VCIssuanceUtil.validateAndGetClientNonce(nonceCacheService, proofValue, log, nonceEndpoint);

                    boolean isValid = proofValidator.validate(clientId, validCNonce,
                            proofValue, supportedProofTypes);
                    if (!isValid) {
                        continue;
                    }
                    if (validCNonce != null) {
                        auditWrapper.logAudit(Action.NONCE_VALIDATION, ActionStatus.SUCCESS,
                                AuditHelper.buildAuditDto(validCNonce, "cNonce"), null);
                    }
                    holderIds.add(proofValidator.getKeyMaterial(proofValue));
                } catch (CertifyException e) {
                    auditWrapper.logAudit(Action.PROOF_VALIDATION, ActionStatus.ERROR,
                            AuditHelper.buildAuditDto(accessTokenHash, "accessTokenHash"), e);
                    throw e;
                }
            }
        }

        if(holderIds.isEmpty()) {
            throw new CertifyException(VCIErrorConstants.INVALID_PROOF, "None of the submitted proofs passed validation.");
        }

        auditWrapper.logAudit(Action.PROOF_VALIDATION, ActionStatus.SUCCESS,
                AuditHelper.buildAuditDto(accessTokenHash, "accessTokenHash"), null);

        return holderIds;
    }
}
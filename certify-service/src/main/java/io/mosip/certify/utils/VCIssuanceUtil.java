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
            else {
                log.error("Nonce claim is not present in proof JWT");
                throw new CertifyException(VCIErrorConstants.INVALID_PROOF, "Nonce claim must be present in proof JWT.");
            }
        }
        catch (ParseException e) {
            // check iff specific error exists for invalid holderKey
            throw new CertifyException(VCIErrorConstants.INVALID_PROOF, "Error encountered during proof jwt parsing.");
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

        if (Objects.equals(cachedNonce, proofJwtNonce)) {
            return cachedNonce;
        } else {
            throw new InvalidNonceException(cachedNonce, cNonceExpire);
        }
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
            String scope, String format,
            CredentialIssuerMetadataDTO credentialIssuerMetadataDTO,
            CredentialRequest credentialRequest) {

        Map<String, CredentialConfigurationSupportedDTO> supportedCredentials =
                credentialIssuerMetadataDTO.getCredentialConfigurationSupportedDTO();

        // Filter entries by scope
        List<Map.Entry<String, CredentialConfigurationSupportedDTO>> scopeEntries = supportedCredentials.entrySet().stream()
                .filter(cm -> Objects.equals(scope, cm.getValue().getScope()))
                .toList();

        if (scopeEntries.isEmpty()) {
            return Optional.empty();
        }

        // Check all scope-matched entries for format and validation
        for (Map.Entry<String, CredentialConfigurationSupportedDTO> entry : scopeEntries) {
            CredentialConfigurationSupportedDTO dto = entry.getValue();
            if (Objects.equals(dto.getFormat(), format)) {
                switch (format) {
                    case VCFormats.LDP_VC:
                        if(!isValidLdpVCRequest(credentialRequest, dto)) continue;
                        break;
                    case VCFormats.MSO_MDOC:
                        if(!isValidMsoMdocRequest(credentialRequest, dto)) continue;
                        break;
                    case VCFormats.VC_SD_JWT:
                        if(!isValidSDJwtRequest(credentialRequest, dto)) continue;
                        break;
                    default:
                        continue;
                }
                // If valid, build and return metadata
                CredentialMetadata credentialMetadata = new CredentialMetadata();
                credentialMetadata.setFormat(dto.getFormat());
                credentialMetadata.setScope(dto.getScope());
                credentialMetadata.setId(entry.getKey());
                credentialMetadata.setProofTypesSupported(dto.getProofTypesSupported());
                if (format.equals(VCFormats.LDP_VC)) {
                    credentialMetadata.setTypes(dto.getCredentialDefinition().getType());
                }
                return Optional.of(credentialMetadata);
            }
        }

        // If no valid entry found for the format, throw format-specific exception
        switch (format) {
            case VCFormats.LDP_VC:
                throw new CertifyException(VCIErrorConstants.INVALID_CREDENTIAL_REQUEST,
                        "No matching ldp_vc credential configuration found for scope: " + scope);
            case VCFormats.MSO_MDOC:
                throw new CertifyException(VCIErrorConstants.INVALID_CREDENTIAL_REQUEST,
                        "No matching mso_mdoc credential configuration found for scope: " + scope);
            case VCFormats.VC_SD_JWT:
                throw new CertifyException(VCIErrorConstants.INVALID_CREDENTIAL_REQUEST,
                        "No matching vc+sd_jwt credential configuration found for scope: " + scope);
            default:
                throw new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT,
                        "No matching credential configuration found for format: " + format);
        }
    }


    private static boolean isValidLdpVCRequest(CredentialRequest credentialRequest, CredentialConfigurationSupportedDTO credentialConfigurationSupportedDTO) {
        if(credentialRequest.getCredential_definition().getContext().size() != credentialConfigurationSupportedDTO.getCredentialDefinition().getContext().size()) {
            return false;
        }

        if(credentialRequest.getCredential_definition().getType().size() != credentialConfigurationSupportedDTO.getCredentialDefinition().getType().size()) {
            return false;
        }

        return new HashSet<>(credentialConfigurationSupportedDTO.getCredentialDefinition().getContext()).containsAll(credentialRequest.getCredential_definition().getContext()) &&
                new HashSet<>(credentialConfigurationSupportedDTO.getCredentialDefinition().getType()).containsAll(credentialRequest.getCredential_definition().getType());
    }

    private static boolean isValidSDJwtRequest(CredentialRequest credentialRequest, CredentialConfigurationSupportedDTO credentialConfigurationSupportedDTO) {
        return Objects.equals(credentialConfigurationSupportedDTO.getVct(), credentialRequest.getVct());
    }

    private static boolean isValidMsoMdocRequest(CredentialRequest credentialRequest, CredentialConfigurationSupportedDTO credentialConfigurationSupportedDTO) {
        return Objects.equals(credentialConfigurationSupportedDTO.getDocType(), credentialRequest.getDoctype());
    }

    public static void validateLdpVcFormatRequest(CredentialRequest credentialRequest,
                                                  CredentialMetadata credentialMetadata) {
        if(!credentialRequest.getCredential_definition().getType().containsAll(credentialMetadata.getTypes()))
            throw new InvalidRequestException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_TYPE);

        //TODO need to validate Credential_definition as JsonLD document, if invalid throw exception
    }
}
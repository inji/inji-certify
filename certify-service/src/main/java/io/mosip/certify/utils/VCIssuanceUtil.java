package io.mosip.certify.utils;

import com.nimbusds.jwt.SignedJWT;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.exception.InvalidNonceException;
import io.mosip.certify.services.VCICacheService;
import io.mosip.certify.api.dto.VCResult;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

public class VCIssuanceUtil {

    private VCIssuanceUtil() {
        // Private constructor to prevent instantiation
    }
    public static String validateAndGetClientNonce(VCICacheService vciCacheService, ParsedAccessToken parsedAccessToken,
                                             int configuredCNonceExpireSeconds, SecurityHelperService securityHelperService,
                                                   CredentialProof credentialProof, Logger log) {
        String accessTokenHash = parsedAccessToken.getAccessTokenHash();
        VCIssuanceTransaction transaction = vciCacheService.getVCITransaction(accessTokenHash);
        String authZServerNonce = (transaction == null) ?
                Optional.ofNullable(parsedAccessToken.getClaims().get(Constants.C_NONCE)).map(Object::toString).orElse("") :
                transaction.getCNonce();

        int cNonceExpire;
        if (transaction == null) {
            int tokenExpiry = determineCNonceExpiry(parsedAccessToken.getClaims().get(Constants.C_NONCE_EXPIRES_IN));
            cNonceExpire = tokenExpiry > 0 ? tokenExpiry : configuredCNonceExpireSeconds;
        } else {
            cNonceExpire = transaction.getCNonceExpireSeconds();
        }

        String proofJwtNonce = null;
        boolean proofJwtHasNonceClaim = false;
        if (credentialProof.getJwt() != null && !credentialProof.getJwt().isBlank()) {
            try {
                SignedJWT proofJwt = SignedJWT.parse(credentialProof.getJwt());
                Map<String, Object> proofClaims = proofJwt.getJWTClaimsSet().getClaims();
                proofJwtHasNonceClaim = proofClaims.containsKey("nonce");
                if (proofJwtHasNonceClaim) {
                    proofJwtNonce = proofJwt.getJWTClaimsSet().getStringClaim("nonce");
                    if (StringUtils.isBlank(proofJwtNonce)) {
                        log.error("Nonce claim is present in proof JWT but is blank");
                        throw new CertifyException(VCIErrorConstants.INVALID_PROOF, "Nonce claim must not be empty.");
                    }
                }
            } catch (ParseException e) {
                // check iff specific error exists for invalid holderKey
                throw new CertifyException(VCIErrorConstants.INVALID_PROOF, "Error encountered during proof jwt parsing.");
            }
        } else if (!StringUtils.isEmpty(authZServerNonce)) {
            // Access token has nonce but no JWT provided to extract proof nonce from
            log.error("JWT proof is required but not provided in credential proof");
            throw new CertifyException(VCIErrorConstants.INVALID_PROOF, "JWT proof is required when nonce is present in access token.");
        }

        if (StringUtils.isEmpty(authZServerNonce) && !proofJwtHasNonceClaim) {
            return null;
        }

        if (StringUtils.isEmpty(authZServerNonce) && proofJwtHasNonceClaim) {
            log.error("Nonce present in proof JWT but missing in access token");
            throw new CertifyException(VCIErrorConstants.INVALID_PROOF, "Nonce must not be present in the proof JWT.");
        }

        long issuedEpoch;
        if (transaction == null) {
            Object iatClaimValue = parsedAccessToken.getClaims().get(JwtClaimNames.IAT);
            issuedEpoch = switch (iatClaimValue) {
                case null -> Instant.MIN.getEpochSecond();
                case Instant instant -> instant.getEpochSecond();
                case Number number -> number.longValue();
                default ->
                        throw new IllegalStateException("IAT claim is of an unexpected type: " + iatClaimValue.getClass().getName());
            };
        } else {
            issuedEpoch = transaction.getCNonceIssuedEpoch();
        }

        boolean nonceExpired = !StringUtils.isEmpty(authZServerNonce) &&
                (cNonceExpire <= 0 ||
                        (issuedEpoch + cNonceExpire) < LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));

        if (nonceExpired) {
            log.error("Client Nonce expired in the access token, generate new authZServerNonce for accessTokenHash: {}",
                    accessTokenHash != null ? accessTokenHash.substring(0, Math.min(accessTokenHash.length(), 10)) + "..." : "null");
            VCIssuanceTransaction newTransaction = createOrUpdateVCITransaction(
                    securityHelperService, configuredCNonceExpireSeconds, vciCacheService, accessTokenHash, transaction);
            authZServerNonce = newTransaction.getCNonce();
            cNonceExpire = newTransaction.getCNonceExpireSeconds();
        }
        if (!StringUtils.isEmpty(authZServerNonce) && StringUtils.isEmpty(proofJwtNonce)) {
            log.error("Nonce missing in the proof JWT but present in access token");
            throw new InvalidNonceException(authZServerNonce, cNonceExpire);
        }

        if (authZServerNonce.equals(proofJwtNonce)) {
            return authZServerNonce;
        } else {
            throw new InvalidNonceException(authZServerNonce, cNonceExpire);
        }
    }

    public static int determineCNonceExpiry(Object nonceExpireSecondsClaim) {
        if (nonceExpireSecondsClaim instanceof Long) {
            return (int)(long)nonceExpireSecondsClaim;
        } else if (nonceExpireSecondsClaim instanceof Integer) {
            return (int)nonceExpireSecondsClaim;
        }
        return 0;
    }

    public static VCIssuanceTransaction createOrUpdateVCITransaction(SecurityHelperService securityHelperService, int cNonceExpireSecondsConfig,
                                                                     VCICacheService vciCacheService, String accessTokenHash, VCIssuanceTransaction existingTransaction) {
        VCIssuanceTransaction transaction = (existingTransaction != null) ? existingTransaction : new VCIssuanceTransaction();
        transaction.setCNonce(securityHelperService.generateSecureRandomString(20));
        transaction.setCNonceIssuedEpoch(LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));
        transaction.setCNonceExpireSeconds(cNonceExpireSecondsConfig);
        return vciCacheService.setVCITransaction(accessTokenHash, transaction);
    }

    @SuppressWarnings("unchecked")
    public static CredentialResponse<?> getCredentialResponse(String format, VCResult<?> vcResult) {
        switch (format) {
            case VCFormats.LDP_VC:
                CredentialResponse<JsonLDObject> ldpVcResponse = new CredentialResponse<>();
                ldpVcResponse.setCredential((JsonLDObject) vcResult.getCredential());
                return ldpVcResponse;

            case VCFormats.VC_SD_JWT:
            case VCFormats.JWT_VC_JSON:
            case VCFormats.JWT_VC_JSON_LD:
            case VCFormats.MSO_MDOC:
                CredentialResponse<String> stringResponse = new CredentialResponse<>();
                stringResponse.setCredential((String) vcResult.getCredential());
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
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

    public static Map<String, Object> convertLatestToVd12(LinkedHashMap<String, Object> vciMetadata) {
        // Create a new map to store the transformed configuration
        if(vciMetadata.containsKey("credential_configurations_supported")) {
            LinkedHashMap<String, Object> supportedCredentials = (LinkedHashMap<String, Object>) vciMetadata.get("credential_configurations_supported");
            Map<String, Object> transformedMap = transformCredentialConfiguration(supportedCredentials);
            vciMetadata.put("credentials_supported", transformedMap);
        }

        vciMetadata.remove("credential_configurations_supported");
        String endpoint = (String)vciMetadata.get("credential_endpoint");
        int issuanceIndex = endpoint.indexOf("issuance/");
        String newEndPoint = endpoint.substring(0, issuanceIndex+9);
        vciMetadata.put("credential_endpoint", newEndPoint + "vd12/credential");
        return vciMetadata;
    }

    public static Map<String, Object> convertLatestToVd11(LinkedHashMap<String, Object> vciMetadata) {
        // Create a list to hold the transformed credentials
        List<Map<String, Object>> credentialsList = new ArrayList<>();

        // Check if the original config contains 'credential_configurations_supported'
        if (vciMetadata.containsKey("credential_configurations_supported")) {
            // Cast the value to a Map
            Map<String, Object> originalCredentials =
                    (Map<String, Object>) vciMetadata.get("credential_configurations_supported");

            // Iterate through each credential
            for (Map.Entry<String, Object> entry : originalCredentials.entrySet()) {
                // Cast the credential configuration
                Map<String, Object> credConfig = (Map<String, Object>) entry.getValue();

                // Create a new transformed credential configuration
                Map<String, Object> transformedCredential = new HashMap<>(credConfig);

                // Add 'id' field with the original key
                transformedCredential.put("id", entry.getKey());

                // Rename 'credential_signing_alg_values_supported' to 'cryptographic_suites_supported'
                if (transformedCredential.containsKey("credential_signing_alg_values_supported")) {
                    transformedCredential.put("cryptographic_suites_supported",
                            transformedCredential.remove("credential_signing_alg_values_supported"));
                }

                // Modify proof_types_supported
                if (transformedCredential.containsKey("proof_types_supported")) {
                    Map<String, Object> proofTypes = (Map<String, Object>) transformedCredential.get("proof_types_supported");
                    transformedCredential.put("proof_types_supported", proofTypes.keySet());
                }

                if(transformedCredential.containsKey("display")) {
                    List<Map<String, Object>> displayMapList = new ArrayList<>((List<Map<String, Object>>)transformedCredential.get("display"));
                    List<Map<String, Object>> newDisplayMapList = new ArrayList<>();
                    for(Map<String, Object> map : displayMapList) {
                        Map<String, Object> displayMap = new HashMap<>(map);
                        displayMap.remove("background_image");
                        newDisplayMapList.add(displayMap);
                    }
                    transformedCredential.put("display", newDisplayMapList);
                }

                // Remove 'order' if it exists
                transformedCredential.remove("order");

                // Add the transformed credential to the list
                credentialsList.add(transformedCredential);
            }

            // Set the transformed credentials in the new configuration
            vciMetadata.put("credentials_supported", credentialsList);
        }

        vciMetadata.remove("credential_configurations_supported");
        vciMetadata.remove("authorization_servers");
        vciMetadata.remove("display");
        String endpoint = (String)vciMetadata.get("credential_endpoint");
        int issuanceIndex = endpoint.indexOf("issuance/");
        String newEndPoint = endpoint.substring(0, issuanceIndex+9);
        vciMetadata.put("credential_endpoint", newEndPoint + "vd11/credential");
        return vciMetadata;
    }

    public static Map<String, Object> transformCredentialConfiguration(LinkedHashMap<String, Object> originalConfig) {
        Map<String, Object> transformedConfig = new LinkedHashMap<>();

        for (Map.Entry<String, Object> entry : originalConfig.entrySet()) {
            Map<String, Object> credentialDetails = (Map<String, Object>) entry.getValue();

            // Create a new map to store modified credential details
            Map<String, Object> transformedCredential = new LinkedHashMap<>(credentialDetails);

            // Replace 'credential_signing_alg_values_supported' with 'cryptographic_suites_supported'
            if (transformedCredential.containsKey("credential_signing_alg_values_supported")) {
                Object signingAlgs = transformedCredential.remove("credential_signing_alg_values_supported");
                transformedCredential.put("cryptographic_suites_supported", signingAlgs);
            }

            // Modify proof_types_supported
            if (transformedCredential.containsKey("proof_types_supported")) {
                Map<String, Object> proofTypes = (Map<String, Object>) transformedCredential.get("proof_types_supported");
                transformedCredential.put("proof_types_supported", proofTypes.keySet());
            }

            if(transformedCredential.containsKey("display")) {
                List<Map<String, Object>> displayMapList = new ArrayList<>((List<Map<String, Object>>)transformedCredential.get("display"));
                List<Map<String, Object>> newDisplayMapList = new ArrayList<>();
                for(Map<String, Object> map : displayMapList) {
                    Map<String, Object> displayMap = new HashMap<>(map);
                    displayMap.remove("background_image");
                    newDisplayMapList.add(displayMap);
                }
                transformedCredential.put("display", newDisplayMapList);
            }

            // Add the modified credential details to the transformed config
            transformedConfig.put(entry.getKey(), transformedCredential);
        }

        return transformedConfig;
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
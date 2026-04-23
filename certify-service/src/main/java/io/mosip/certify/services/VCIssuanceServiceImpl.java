/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.VCIExchangeException;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.spi.VCIssuancePlugin;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.api.util.AuditHelper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.CredentialConfigurationSupported;
import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialResponse;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.utils.VCIssuanceUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.*;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.plugin-mode", havingValue = "VCIssuance")
public class VCIssuanceServiceImpl implements VCIssuanceService {

    @Autowired
    private ParsedAccessToken parsedAccessToken;

    @Autowired
    private VCIssuancePlugin vcIssuancePlugin;

    @Autowired
    private ProofValidatorFactory proofValidatorFactory;

    @Autowired
    private VCICacheService vciCacheService;

    @Autowired
    private AuditPlugin auditWrapper;

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @Override
    public CredentialResponse getCredential(CredentialRequest credentialRequest) {
        List<VCResult<?>> vcResults = new ArrayList<>();

        if(!parsedAccessToken.isActive())
            throw new NotAuthenticatedException();

        String scopeClaim = (String) parsedAccessToken.getClaims().getOrDefault("scope", "");
        CredentialConfigurationSupported credentialConfigurationSupported = null;
        for(String scope : scopeClaim.split(Constants.SPACE)) {
            Optional<CredentialConfigurationSupported> result = VCIssuanceUtil.getScopeCredentialMapping(scope,credentialRequest.getCredentialConfigId() ,credentialConfigurationService.fetchCredentialIssuerMetadata());
            if(result.isPresent()) {
                credentialConfigurationSupported = result.get(); //considering only first credential scope
                break;
            }
        }

        if(credentialConfigurationSupported == null) {
            log.error("No credential mapping found for the provided scope {}", scopeClaim);
            throw new CertifyException(VCIErrorConstants.INVALID_SCOPE);
        }

        // 3. Proof Validation
        String clientId = (String) parsedAccessToken.getClaims().get(Constants.CLIENT_ID);
        String accessTokenHash = parsedAccessToken.getAccessTokenHash();
        List<String> holderIds = VCIssuanceUtil.validateProofsAndGetHolderIds(credentialRequest,credentialConfigurationSupported,
                clientId, accessTokenHash, auditWrapper,proofValidatorFactory,vciCacheService,credentialConfigurationService);
        for (String holderId : holderIds) {
            vcResults.add(getVerifiableCredential(credentialConfigurationSupported, holderId));
        }

        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.SUCCESS,
                AuditHelper.buildAuditDto(accessTokenHash, "accessTokenHash"), null);
        return VCIssuanceUtil.getCredentialResponse(credentialConfigurationSupported.getFormat(), vcResults);
    }

    @Override
    public Map<String, Object> getDIDDocument() {
        throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_IN_CURRENT_PLUGIN_MODE);
    }

    private VCResult<?> getVerifiableCredential(CredentialConfigurationSupported credentialConfigurationSupported,
                                                String holderId) {
        parsedAccessToken.getClaims().put("accessTokenHash", parsedAccessToken.getAccessTokenHash());
        VCRequestDto vcRequestDto = new VCRequestDto();
        vcRequestDto.setFormat(credentialConfigurationSupported.getFormat());


        VCResult<?> vcResult = null;
        try {
            switch (credentialConfigurationSupported.getFormat()) {
                case "ldp_vc" :
                    vcRequestDto.setContext(credentialConfigurationSupported.getContext());
                    vcRequestDto.setType(credentialConfigurationSupported.getType());
                    vcRequestDto.setCredentialSubject(credentialConfigurationSupported.getCredentialSubject());
                    vcResult = vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(vcRequestDto, holderId,
                            parsedAccessToken.getClaims());
                    break;

                // jwt_vc_json & jwt_vc_json-ld cases are merged
                case "jwt_vc_json-ld" :
                case "jwt_vc_json" :
                    vcRequestDto.setContext(credentialConfigurationSupported.getContext());
                    vcRequestDto.setType(credentialConfigurationSupported.getType());
                    vcRequestDto.setCredentialSubject(credentialConfigurationSupported.getCredentialSubject());
                    vcResult = vcIssuancePlugin.getVerifiableCredential(vcRequestDto, holderId,
                            parsedAccessToken.getClaims());
                    break;
                case VCFormats.MSO_MDOC :
                    vcRequestDto.setClaims(credentialConfigurationSupported.getClaims());
                    vcRequestDto.setDoctype( credentialConfigurationSupported.getDocType());
                    vcResult = vcIssuancePlugin.getVerifiableCredential(vcRequestDto, holderId,
                            parsedAccessToken.getClaims());
                    break;
                default:
                    throw new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT, "Invalid or unsupported VC format requested.");
            }
        } catch (VCIExchangeException e) {
            throw new CertifyException(e.getErrorCode());
        }

        if(vcResult != null && vcResult.getCredential() != null)
            return vcResult;

        log.error("Failed to generate VC : {}", vcResult);
        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.ERROR,
                AuditHelper.buildAuditDto(parsedAccessToken.getAccessTokenHash(), "accessTokenHash"), null);
        throw new CertifyException(ErrorConstants.VC_ISSUANCE_FAILED);
    }

}
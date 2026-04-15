package io.mosip.certify;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialResponse;
import io.mosip.certify.core.dto.CredentialWrapper;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.VCIssuanceService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@ConditionalOnProperty(value = "mosip.certify.plugin-mode", havingValue = "VCIssuance")
public class TestVCIssuanceServiceImpl implements VCIssuanceService {
    @Override
    public  CredentialResponse getCredential(CredentialRequest credentialRequest) {
        CredentialWrapper credentialWrapper1 = new CredentialWrapper();
        credentialWrapper1.setCredential( "Mock Credential1");
        CredentialWrapper credentialWrapper2 = new CredentialWrapper();
        credentialWrapper2.setCredential( "Mock Credential2");
        CredentialResponse credentialResponse = new CredentialResponse();
        List<CredentialWrapper> credentials = new ArrayList<>();
        credentials.add(credentialWrapper1);
        credentials.add(credentialWrapper2);
        credentialResponse.setFormat("mock-format");
        credentialResponse.setC_nonce("fake-nonce");
        credentialResponse.setAcceptance_token("fake-token");
        credentialResponse.setC_nonce_expires_in(3600);
        return credentialResponse;
    }

    @Override
    public Map<String, Object> getDIDDocument() {
        throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_IN_CURRENT_PLUGIN_MODE);
    }
}

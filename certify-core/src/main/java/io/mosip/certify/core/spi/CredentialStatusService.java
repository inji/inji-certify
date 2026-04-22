package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;

public interface CredentialStatusService {
    CredentialStatusResponse updateCredentialStatus(UpdateCredentialStatusRequest updateCredentialStatusRequest);
}

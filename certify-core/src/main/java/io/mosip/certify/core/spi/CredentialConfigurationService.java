package io.mosip.certify.core.spi;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.certify.core.dto.*;

public interface CredentialConfigurationService {

    CredentialConfigResponse addCredentialConfigurationV2(CredentialConfigurationDTOV2 credentialConfigurationDTO) throws JsonProcessingException;

    CredentialConfigurationDTOV2 getCredentialConfigurationByIdV2(String id) throws JsonProcessingException;

    CredentialConfigResponse updateCredentialConfigurationV2(String id, CredentialConfigurationDTOV2 credentialConfigurationDTO) throws JsonProcessingException;

    String deleteCredentialConfigurationById(String id);

    CredentialIssuerMetadataDTOV2 fetchCredentialIssuerMetadataV2();
}
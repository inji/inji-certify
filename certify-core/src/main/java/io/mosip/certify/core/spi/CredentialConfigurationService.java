package io.mosip.certify.core.spi;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.certify.core.dto.*;

public interface CredentialConfigurationService {

    CredentialConfigResponse addCredentialConfiguration(CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException;

    CredentialConfigResponse addCredentialConfigurationV2(CredentialConfigurationDTOV2 credentialConfigurationDTO) throws JsonProcessingException;

    CredentialConfigurationDTO getCredentialConfigurationById(String id) throws JsonProcessingException;

    CredentialConfigurationDTOV2 getCredentialConfigurationByIdV2(String id) throws JsonProcessingException;

    CredentialConfigResponse updateCredentialConfiguration(String id, CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException;

    CredentialConfigResponse updateCredentialConfigurationV2(String id, CredentialConfigurationDTOV2 credentialConfigurationDTO) throws JsonProcessingException;

    String deleteCredentialConfigurationById(String id);

    CredentialIssuerMetadataDTO fetchCredentialIssuerMetadata(String version);

    CredentialIssuerMetadataDTOV2 fetchCredentialIssuerMetadataV2(String version);
}

package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.Map;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialIssuerMetadataVD12DTOV2 extends CredentialIssuerMetadataDTOV2 {
    @JsonProperty("credentials_supported")
    private Map<String, CredentialConfigurationSupportedDTOV2> credentialConfigurationSupportedDTO;

    @Override
    public Map<String, CredentialConfigurationSupportedDTOV2> getCredentialConfigurationSupportedDTOV2() {
        return credentialConfigurationSupportedDTO;
    }

    public void setCredentialConfigurationSupportedDTOV2(Map<String, CredentialConfigurationSupportedDTOV2> credentialConfigurationSupportedDTO) {
        this.credentialConfigurationSupportedDTO = credentialConfigurationSupportedDTO;
    }
}

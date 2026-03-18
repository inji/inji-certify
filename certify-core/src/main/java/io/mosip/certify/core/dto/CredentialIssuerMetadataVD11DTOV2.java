package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Data
@JsonInclude
public class CredentialIssuerMetadataVD11DTOV2 extends CredentialIssuerMetadataDTOV2 {
    @JsonProperty("credentials_supported")
    private List<CredentialConfigurationSupportedDTOV2> credentialConfigurationSupportedDTO;

    @Override
    public Map<String, CredentialConfigurationSupportedDTOV2> getCredentialConfigurationSupportedDTOV2() {
        return credentialConfigurationSupportedDTO.stream()
                .collect(Collectors.toMap(CredentialConfigurationSupportedDTOV2::getId, dto -> dto));
    }

    public void setCredentialConfigurationSupportedDTOV2(List<CredentialConfigurationSupportedDTOV2> credentialConfigurationSupportedDTO) {
        this.credentialConfigurationSupportedDTO = credentialConfigurationSupportedDTO;
    }
}

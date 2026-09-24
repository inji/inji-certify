package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.constants.Constants;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialConfigurationSupportedDTO {

    private String format;

    @JsonProperty("doctype")
    private String docType;

    private String scope;

    private String id;

    @JsonProperty(Constants.CRYPTOGRAPHIC_BINDING_METHODS_SUPPORTED)
    private List<String> cryptographicBindingMethodsSupported;

    @JsonProperty("cryptographic_suites_supported")
    private List<String> cryptographicSuitesSupported;

    @JsonProperty(Constants.CREDENTIAL_SIGNING_ALG_VALUES_SUPPORTED)
    private List<Object> credentialSigningAlgValuesSupported;

    @JsonProperty(Constants.PROOF_TYPES_SUPPORTED)
    private Map<String, Object> proofTypesSupported;

    @JsonProperty("credential_definition")
    private CredentialDefinition credentialDefinition;

    private String vct;

    @JsonProperty("credential_metadata")
    private CredentialMetadataDTO credentialMetadataDTO;
}

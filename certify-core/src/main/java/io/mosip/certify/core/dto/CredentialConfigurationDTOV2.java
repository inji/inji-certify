package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialConfigurationDTOV2 {

    private String vcTemplate;

    private String credentialConfigKeyId;

    private List<String> contextURLs;

    private List<String> credentialTypes;

    @NotNull(message = ErrorConstants.INVALID_VC_FORMAT)
    private String credentialFormat;

    private String didUrl;

    private String keyManagerAppId;

    private String keyManagerRefId;

    private String signatureAlgo; //Can be called as Proof algorithm

    private String signatureCryptoSuite;

    private String sdClaim;

    @Valid
    @NotNull(message = ErrorConstants.INVALID_METADATA_DISPLAY)
    private List<MetaDataDisplayDTOV2> metaDataDisplay;

    private List<String> displayOrder;

    @NotNull(message = VCIErrorConstants.INVALID_SCOPE)
    private String scope;

    @JsonProperty("credentialSubjectDefinition")
    private Map<String, CredentialSubjectParametersDTO> credentialSubjectDefinition;

    @JsonProperty("msoMdocClaims")
    private Map<String, Map<String, ClaimsDisplayFieldsConfigDTO>> msoMdocClaims;

    @JsonProperty("sdJwtClaims")
    private Map<String, ClaimsDisplayFieldsConfigDTO> sdJwtClaims;

    @JsonProperty("doctype")
    private String docType;

    @JsonProperty("sdJwtVct")
    private String sdJwtVct;

    private List<Map<String, String>> pluginConfigurations;

    private List<String> credentialStatusPurposes;

    @JsonDeserialize(using = QrSettingsDeserializer.class)
    private List<Map<String, Object>> qrSettings;

    private String qrSignatureAlgo;
}

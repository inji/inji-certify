package io.mosip.certify.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.dto.PresentationDefinition;
import lombok.Data;

@Data
public class VerifyServiceConfig {
    @JsonProperty("presentation_definition")
    private PresentationDefinition presentationDefinition;
}


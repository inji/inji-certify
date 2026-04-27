package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import java.util.List;

@Data
public class CredentialMetadataDTO {

    private List<MetaDataDisplayDTO> display;

    private List<Claims> claims;

    @Data
    public static class Claims {

        private List<String> path;

        @JsonInclude(JsonInclude.Include.NON_DEFAULT)
        private boolean mandatory;

        private List<ClaimsDisplayFieldsConfigDTO.Display> display;

    }
}


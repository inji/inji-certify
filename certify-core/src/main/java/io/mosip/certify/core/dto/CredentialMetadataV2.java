package io.mosip.certify.core.dto;

import lombok.Data;
import java.util.List;

@Data
public class CredentialMetadataV2 {

    private List<MetaDataDisplayDTOV2> display;

    private List<Claims> claims;

    @Data
    public static class Claims {

        private List<String> path;

        private List<ClaimsDisplayFieldsConfigDTO.Display> display;

    }
}


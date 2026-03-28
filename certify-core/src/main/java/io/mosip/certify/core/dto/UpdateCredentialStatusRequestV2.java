package io.mosip.certify.core.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class UpdateCredentialStatusRequestV2 {
    @NotNull
    @Valid
    private CredentialStatusDtoV2 credentialStatus;

    @NotNull
    private Boolean status;

    @Data
    public static class CredentialStatusDtoV2 {
        private String id;
        private String type;
        private String statusPurpose;
        @NotNull
        @Min(value = 0, message = "statusListIndex must be a non-negative integer")
        private Long statusListIndex;
        @NotNull
        private String statusListCredential;
    }
}

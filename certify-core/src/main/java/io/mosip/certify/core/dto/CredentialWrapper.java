package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@Data
public class CredentialWrapper<T> {
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private T credential;
}

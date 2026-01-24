package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Grant {

    @JsonProperty("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    private PreAuthorizedCodeGrantType preAuthorizedCode;

    @JsonProperty("authorization_code")
    private AuthorizationCodeGrantType authorizationCode;

    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class PreAuthorizedCodeGrantType {

        @JsonProperty("pre-authorized_code")
        private String preAuthorizedCode;

        @JsonProperty("tx_code")
        private TxCode txCode;
    }

    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class AuthorizationCodeGrantType {

        @JsonProperty("issuer_state")
        private String issuerState;

        @JsonProperty("authorization_server")
        private String authorizationServer;
    }
}
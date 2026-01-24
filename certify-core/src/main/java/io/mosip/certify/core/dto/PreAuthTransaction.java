package io.mosip.certify.core.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.io.Serializable;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PreAuthTransaction extends VCIssuanceTransaction implements Serializable {
    private static final long serialVersionUID = 1L;

    private String credentialConfigurationId;
    private Map<String, Object> claims;
    private long createdAt;

    @Builder
    public PreAuthTransaction(String cNonce, long cNonceIssuedEpoch, int cNonceExpireSeconds, String credentialConfigurationId, Map<String, Object> claims, long createdAt) {
        super();
        this.setCNonce(cNonce);
        this.setCNonceIssuedEpoch(cNonceIssuedEpoch);
        this.setCNonceExpireSeconds(cNonceExpireSeconds);
        this.credentialConfigurationId = credentialConfigurationId;
        this.claims = claims;
        this.createdAt = createdAt;
    }
}

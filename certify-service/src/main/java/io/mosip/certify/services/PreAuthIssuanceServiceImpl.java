package io.mosip.certify.services;


import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.dto.PreAuthTransaction;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.Map;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.integration.data-provider-plugin", havingValue = "PreAuthDataProviderPlugin")
public class PreAuthIssuanceServiceImpl implements DataProviderPlugin {

    @Autowired
    private VCICacheService vciCacheService;
    @Autowired
    private ParsedAccessToken parsedAccessToken;

    @Override
    public JSONObject fetchData(Map<String, Object> identityDetails) throws DataProviderExchangeException {
        // Validate parsedAccessToken and accessTokenHash
        if (parsedAccessToken == null || parsedAccessToken.getAccessTokenHash() == null || parsedAccessToken.getAccessTokenHash().isEmpty()) {
            log.error("Invalid or missing access token hash in parsedAccessToken");
            throw new DataProviderExchangeException("Access token hash is null or empty");
        }

        String accessTokenHash = parsedAccessToken.getAccessTokenHash();
        Object cachedObject = vciCacheService.getVCITransaction(accessTokenHash);

        // Validate the cached object type
        if (!(cachedObject instanceof PreAuthTransaction cachedTransaction)) {
            log.error("Invalid or null cached transaction for access token hash: {}", accessTokenHash);
            throw new DataProviderExchangeException("Cached transaction is null or of incorrect type");
        }

        // Validate claims in the cached transaction
        if (cachedTransaction.getClaims() == null || cachedTransaction.getClaims().isEmpty()) {
            log.error("No claims found in cached transaction for access token hash: {}", accessTokenHash);
            throw new DataProviderExchangeException("Cached transaction claims are null or empty");
        }

        log.info("Using cached claims from pre-auth flow for credential generation");
        return new JSONObject(cachedTransaction.getClaims());
    }
}

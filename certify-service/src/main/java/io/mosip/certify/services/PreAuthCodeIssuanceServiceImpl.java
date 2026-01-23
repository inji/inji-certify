package io.mosip.certify.services;


import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.dto.Transaction;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.Map;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.integration.data-provider-plugin", havingValue = "PreAuthCodeDataProviderPlugin")
public class PreAuthCodeIssuanceServiceImpl implements DataProviderPlugin {

    @Autowired
    private VCICacheService vciCacheService;
    @Autowired
    private ParsedAccessToken parsedAccessToken;

    @Override
    public JSONObject fetchData(Map<String, Object> identityDetails) throws DataProviderExchangeException {
        Transaction cachedTransaction = vciCacheService.getTransaction(parsedAccessToken.getAccessTokenHash());
        if (cachedTransaction != null && cachedTransaction.getClaims() != null && !cachedTransaction.getClaims().isEmpty()) {
            log.info("Using cached claims from pre-auth flow for credential generation");
            return new JSONObject(cachedTransaction.getClaims());
        }
        log.error("No cached claims found for pre-auth flow with access token hash: {}", parsedAccessToken.getAccessTokenHash());
        throw new DataProviderExchangeException();
    }
}

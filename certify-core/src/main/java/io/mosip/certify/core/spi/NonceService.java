package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.NonceResponse;

public interface NonceService {
    NonceResponse generateNonce();
}

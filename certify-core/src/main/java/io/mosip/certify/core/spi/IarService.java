/*
 * Copyright 2024 Modular Open Source Identity Platform
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.IarRequest;
import io.mosip.certify.core.dto.OAuthTokenRequest;
import io.mosip.certify.core.dto.OAuthTokenResponse;
import io.mosip.certify.core.exception.CertifyException;

/**
 * Interactive Authorization Request (IAR) Service Interface
 * Handles authorization requests for OpenID4VCI credential issuance
 */
public interface IarService {


    /**
     * Handle unified IAR request
     * Determines whether this is an initial authorization request or VP presentation response
     * and routes to the appropriate processing method
     * 
     * @param iarRequest The interactive authorization request containing either authorization or presentation data
     * @return Object containing either IarResponse or IarAuthorizationResponse
     * @throws CertifyException if request processing fails
     */
    Object handleIarRequest(IarRequest iarRequest) throws CertifyException;

    /**
     * Process OAuth Token Request (Step 19-20)
     * Exchanges authorization code for access token
     * 
     * @param tokenRequest The token request containing authorization code
     * @return OAuthTokenResponse with access_token
     * @throws CertifyException if token request processing fails
     */
    OAuthTokenResponse processTokenRequest(OAuthTokenRequest tokenRequest) throws CertifyException;
}

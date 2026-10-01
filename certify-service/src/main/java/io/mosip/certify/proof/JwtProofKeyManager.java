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
package io.mosip.certify.proof;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;

import java.util.Optional;
// Should this method be an abstract class instead of an interface for managing holder's key in JWK format?
/**
 * {@link JwtProofKeyManager} helps in managing the holder's key.
 */
public interface JwtProofKeyManager {
    /**
     * getKeyFromHeader is a method that returns the JWK from the JWSHeader.
     * @param header is the JWSHeader, where the pub key can be in kid or in jwk form
     * @return the JWK
     */
    // TODO: name this method better, maybe getKey(JWSHeader)
    public Optional<JWK> getKeyFromHeader(JWSHeader header);

    /**
     * @param header is the JWSHeader, where the pub key can be in kid or in jwk form
     * @return the DID form of the key
     */
    public Optional<String> getDID(JWSHeader header);
}

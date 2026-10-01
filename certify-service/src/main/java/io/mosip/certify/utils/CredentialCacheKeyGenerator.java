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
package io.mosip.certify.utils;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

import java.util.Optional;

import static io.mosip.certify.core.constants.Constants.DELIMITER;

@Component("credentialCacheKeyGenerator") // Bean name used in SpEL
public class CredentialCacheKeyGenerator {

    private static final Logger log = LoggerFactory.getLogger(CredentialCacheKeyGenerator.class);
    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

    @Autowired
    private CacheManager cacheManager;

    public String generateKeyFromCredentialConfigKeyId(String credentialConfigKeyId) {
        if (credentialConfigKeyId == null) {
            log.warn("generateKeyFromConfigId called with null configId for cache key generation.");
            return null;
        }

        Optional<CredentialConfig> configOpt = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId);

        if (configOpt.isPresent()) {
           CredentialConfig config = configOpt.get();

           if(config.getCredentialFormat().equals(VCFormats.DC_SD_JWT)){
                return String.join(DELIMITER,
                          config.getCredentialFormat(),
                          config.getSdJwtVct());
           }

           return String.join(DELIMITER,
                       config.getCredentialType(),
                       config.getContext(),
                       config.getCredentialFormat());
        }

        return  "default-key";
    }
}
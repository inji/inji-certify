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
package io.mosip.certify.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.dto.AuthorizationDetail;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Spring Converter to parse authorization_details from JSON string to List<AuthorizationDetail>
 * This is needed to handle form-urlencoded requests where authorization_details comes as a JSON string
 */
@Slf4j
@Component
public class AuthorizationDetailsConverter implements Converter<String, List<AuthorizationDetail>> {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public List<AuthorizationDetail> convert(String source) {
        if (source == null || source.trim().isEmpty()) {
            return null;
        }

        try {
            log.debug("Converting authorization_details from string: {}", source);
            List<AuthorizationDetail> result = objectMapper.readValue(
                source,
                new TypeReference<List<AuthorizationDetail>>() {}
            );
            log.debug("Successfully converted authorization_details, size: {}", result != null ? result.size() : 0);
            return result;
        } catch (Exception e) {
            log.error("Failed to parse authorization_details from string: {}", source, e);
            throw new IllegalArgumentException("Invalid authorization_details format: " + e.getMessage(), e);
        }
    }
}


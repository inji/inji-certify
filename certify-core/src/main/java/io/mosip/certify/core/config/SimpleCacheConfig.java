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
package io.mosip.certify.core.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CachingConfigurerSupport;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.google.common.cache.CacheBuilder;

@ConditionalOnProperty(value = "spring.cache.type", havingValue = "simple")
@Configuration
public class SimpleCacheConfig extends CachingConfigurerSupport {

    @Value("${mosip.certify.cache.names}")
    private List<String> cacheNames;

    @Value("#{${mosip.certify.cache.size}}")
    private Map<String, Integer> cacheMaxSize;

    @Value("#{${mosip.certify.cache.expire-in-seconds}}")
    private Map<String, Integer> cacheExpireInSeconds;


    @Bean
    @Override
    public CacheManager cacheManager() {
        SimpleCacheManager cacheManager = new SimpleCacheManager();
        List<Cache> caches = new ArrayList<>();
        for(String name : cacheNames) {
            caches.add(buildMapCache(name));
        }
        cacheManager.setCaches(caches);
        return cacheManager;
    }

    private ConcurrentMapCache buildMapCache(String name) {
        return new ConcurrentMapCache(name,
                CacheBuilder.newBuilder()
                        .expireAfterWrite(cacheExpireInSeconds.getOrDefault(name, 60), TimeUnit.SECONDS)
                        .maximumSize(cacheMaxSize.getOrDefault(name, 100))
                        .build()
                        .asMap(), true);
    }
}

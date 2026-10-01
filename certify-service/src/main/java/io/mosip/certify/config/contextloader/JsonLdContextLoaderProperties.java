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
package io.mosip.certify.config.contextloader;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@Getter
@Validated
@Setter
@ConfigurationProperties(prefix = "mosip.certify.jsonld")
public class JsonLdContextLoaderProperties {

    @Valid
    private final Cache cache = new Cache();

    @Valid
    private final Remote remote = new Remote();

    @NotNull
    @Valid
    private Map<String, Context> contexts = defaultContexts();

    @Setter
    @Getter
    public static class Cache {

        private boolean enabled = true;

        @Min(0)
        private int maxEntries = 256;

        @NotNull
        private Duration ttl = Duration.ofHours(24);

        public void setTtl(Duration ttl) {
            this.ttl = (ttl != null) ? ttl : Duration.ZERO;
        }
    }

    @Getter
    @Setter
    public static class Remote {

        private boolean enabled = true;

        /** allow remote fetch for contexts whose host is not in {@code allowedHosts} */
        private boolean allowUnknown = false;

        /** maximum number of HTTP redirects to follow when fetching a remote context */
        @Min(0)
        private int maxRedirects = 5;

        @NotNull
        private Set<String> allowedHosts = new LinkedHashSet<>();

        public void setAllowedHosts(Set<String> allowedHosts) {
            LinkedHashSet<String> norm = new LinkedHashSet<>();
            if (allowedHosts != null) {
                for (String h : allowedHosts) {
                    if (h == null) continue;
                    String v = h.trim().toLowerCase(Locale.ROOT);
                    if (!v.isEmpty()) norm.add(v);
                }
            }
            this.allowedHosts = norm;
        }
    }

    @Setter
    @Getter
    public static class Context {
        @NotBlank
        private String resource;
        private boolean preload = true;
        private boolean cache = true;
    }

    private static Map<String, Context> defaultContexts() {
        Map<String, Context> m = new LinkedHashMap<>();
        m.put("https://www.w3.org/2018/credentials/v1", ctx("classpath:/contexts/credentials-v1.jsonld"));
        m.put("https://www.w3.org/ns/credentials/v2", ctx("classpath:/contexts/credentials-v2.jsonld"));
        m.put("https://w3id.org/security/suites/ed25519-2020/v1", ctx("classpath:/contexts/security-v1.jsonld"));
        return m;
    }

    private static Context ctx(String resource) {
        Context c = new Context();
        c.setResource(resource);
        c.setPreload(true);
        c.setCache(true);
        return c;
    }
}


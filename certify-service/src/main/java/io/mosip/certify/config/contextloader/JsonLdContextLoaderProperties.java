/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
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


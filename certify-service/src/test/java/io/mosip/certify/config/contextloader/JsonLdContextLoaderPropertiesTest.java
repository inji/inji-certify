package io.mosip.certify.config.contextloader;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class JsonLdContextLoaderPropertiesTest {

    @Test
    void cache_setTtl_null_setsZero() {
        JsonLdContextLoaderProperties props = new JsonLdContextLoaderProperties();
        props.getCache().setTtl(null);
        assertEquals(Duration.ZERO, props.getCache().getTtl());
    }

    @Test
    void remote_setAllowedHosts_null_setsEmpty() {
        JsonLdContextLoaderProperties props = new JsonLdContextLoaderProperties();
        props.getRemote().setAllowedHosts(null);
        assertNotNull(props.getRemote().getAllowedHosts());
        assertTrue(props.getRemote().getAllowedHosts().isEmpty());
    }

    @Test
    void remote_setAllowedHosts_normalizesLowercaseAndTrims() {
        JsonLdContextLoaderProperties props = new JsonLdContextLoaderProperties();

        LinkedHashSet<String> in = new LinkedHashSet<>();
        in.add("  WwW.W3.Org  ");
        in.add("w3id.org");
        in.add("   "); // should be ignored

        props.getRemote().setAllowedHosts(in);

        Set<String> out = props.getRemote().getAllowedHosts();
        assertTrue(out.contains("www.w3.org"));
        assertTrue(out.contains("w3id.org"));
        assertFalse(out.contains("  WwW.W3.Org  "));
    }

    @Test
    void defaults_contexts_present() {
        JsonLdContextLoaderProperties props = new JsonLdContextLoaderProperties();
        assertNotNull(props.getContexts());
        assertFalse(props.getContexts().isEmpty(), "Default contexts should exist");
        assertTrue(props.getContexts().containsKey("https://www.w3.org/2018/credentials/v1"));
        assertTrue(props.getContexts().containsKey("https://w3id.org/security/suites/ed25519-2020/v1"));
    }
}

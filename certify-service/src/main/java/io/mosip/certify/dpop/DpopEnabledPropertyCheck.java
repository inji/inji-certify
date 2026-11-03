package io.mosip.certify.dpop;

import org.springframework.boot.LazyInitializationExcludeFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * Refuses to start unless {@code mosip.certify.dpop.enabled} is absent, {@code true} or
 * {@code false}, ignoring case.
 *
 * <p>{@link DpopProofValidator}'s {@code @ConditionalOnProperty} is a string match, so
 * {@code yes}, {@code on}, {@code 1} or a typo would quietly turn DPoP off. The check lives
 * here rather than in a filter because the filters are profile-scoped, and a bad value must
 * fail startup under every profile.
 *
 * <p>The value is read from the {@link Environment}, as the condition reads it, rather than
 * through {@code @Value}: {@code @Value} evaluates SpEL, so {@code #{'true'}} would pass here
 * while the condition sees the raw text and leaves DPoP off.
 */
@Configuration
public class DpopEnabledPropertyCheck {

    static final String DPOP_ENABLED = "mosip.certify.dpop.enabled";

    public DpopEnabledPropertyCheck(Environment environment) {
        String dpopEnabled = environment.getProperty(DPOP_ENABLED, "true");
        if (!"true".equalsIgnoreCase(dpopEnabled) && !"false".equalsIgnoreCase(dpopEnabled)) {
            throw new IllegalStateException(
                    DPOP_ENABLED + " must be true or false, but was '" + dpopEnabled + "'");
        }
    }

    /**
     * Nothing injects this check, so with {@code spring.main.lazy-initialization=true} it
     * would never be created and a bad value would start silently. Keep it eager.
     */
    @Bean
    static LazyInitializationExcludeFilter dpopEnabledPropertyCheckIsEager() {
        return LazyInitializationExcludeFilter.forBeanTypes(DpopEnabledPropertyCheck.class);
    }
}

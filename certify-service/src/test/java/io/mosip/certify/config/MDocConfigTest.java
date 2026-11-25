package io.mosip.certify.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MDocConfigTest {

    // MDocConfig is a @Component in the application, bound from the mosip.certify.mdoc properties.
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(PropertyBinding.class, MDocConfig.class);

    @EnableConfigurationProperties
    static class PropertyBinding {
    }

    @Test
    void should_start_when_digestAlgorithmIsOneIsoAllows() {
        for (String algorithm : new String[]{"SHA-256", "SHA-384", "SHA-512"}) {
            MDocConfig config = new MDocConfig();
            config.setDigestAlgorithm(algorithm);
            assertDoesNotThrow(config::validateDigestAlgorithm, algorithm);
        }
    }

    @Test
    void should_refuseToStart_when_digestAlgorithmIsNotOneIsoAllows() {
        MDocConfig config = new MDocConfig();
        config.setDigestAlgorithm("SHA-1");

        IllegalStateException exception = assertThrows(IllegalStateException.class, config::validateDigestAlgorithm);
        assertTrue(exception.getMessage().contains("mosip.certify.mdoc.digest-algorithm"));
    }

    @Test
    void should_start_when_defaultsAreUsed() {
        assertDoesNotThrow(new MDocConfig()::validate);
    }

    @Test
    void should_refuseToStart_when_validityPeriodIsLessThanAYear() {
        MDocConfig config = new MDocConfig();
        config.setValidityPeriodYears(0);

        IllegalStateException exception = assertThrows(IllegalStateException.class, config::validate);
        assertTrue(exception.getMessage().contains("mosip.certify.mdoc.validity-period-years"));
    }

    @Test
    void should_bindTheConfiguredValues_when_contextStarts() {
        contextRunner.withPropertyValues("mosip.certify.mdoc.digest-algorithm=SHA-384",
                        "mosip.certify.mdoc.validity-period-years=5")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    MDocConfig config = context.getBean(MDocConfig.class);
                    assertThat(config.getDigestAlgorithm()).isEqualTo("SHA-384");
                    assertThat(config.getValidityPeriodYears()).isEqualTo(5);
                });
    }

    @Test
    void should_failStartup_when_digestAlgorithmPropertyIsNotOneIsoAllows() {
        contextRunner.withPropertyValues("mosip.certify.mdoc.digest-algorithm=SHA-1")
                .run(context -> assertThat(context).hasFailed()
                        .getFailure()
                        .rootCause()
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("mosip.certify.mdoc.digest-algorithm is 'SHA-1'"));
    }

    @Test
    void should_failStartup_when_validityPeriodPropertyIsLessThanAYear() {
        contextRunner.withPropertyValues("mosip.certify.mdoc.validity-period-years=0")
                .run(context -> assertThat(context).hasFailed()
                        .getFailure()
                        .rootCause()
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("mosip.certify.mdoc.validity-period-years is 0"));
    }
}

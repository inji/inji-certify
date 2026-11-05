package io.mosip.certify.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MDocConfigTest {

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
}

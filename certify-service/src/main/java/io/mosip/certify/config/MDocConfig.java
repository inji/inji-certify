package io.mosip.certify.config;

import io.mosip.certify.utils.MDocProcessor;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Map;

@Data
@Component
@ConfigurationProperties(prefix = "mosip.certify.mdoc")
public class MDocConfig {

    /**
     * Default digest algorithm for MSO (e.g., "SHA-256")
     */
    private String digestAlgorithm = "SHA-256";

    /**
     * MSO version string
     */
    private String msoVersion = "1.0";

    /**
     * Default validity period in years
     */
    private int validityPeriodYears = 2;

    /**
     * DocType configurations per template
     * Key: template name, Value: docType identifier
     */
    private Map<String, String> docTypes;

    /**
     * Namespace configurations per template
     * Key: template name, Value: default namespace
     */
    private Map<String, String> namespaces;

    /**
     * Field mapping configurations per template
     * Format: templateName.sourceField = targetNamespace:targetField
     */
    private Map<String, Map<String, String>> fieldMappings;

    /** A configuration the MSO can't be built from is refused at startup rather than at issuance. */
    @PostConstruct
    public void validate() {
        validateDigestAlgorithm();
        validateValidityPeriod();
    }

    public void validateDigestAlgorithm() {
        if (!MDocProcessor.SUPPORTED_DIGEST_ALGORITHMS.contains(digestAlgorithm)) {
            throw new IllegalStateException("mosip.certify.mdoc.digest-algorithm is '" + digestAlgorithm
                    + "'; it must be one of " + MDocProcessor.SUPPORTED_DIGEST_ALGORITHMS + " (ISO/IEC 18013-5, 9.1.2.5).");
        }
    }

    /** validUntil is validityPeriodYears after validFrom and must be later (ISO/IEC 18013-5, 9.1.2.4). */
    public void validateValidityPeriod() {
        if (validityPeriodYears < 1) {
            throw new IllegalStateException("mosip.certify.mdoc.validity-period-years is " + validityPeriodYears
                    + "; it must be at least 1 so that validUntil is after validFrom (ISO/IEC 18013-5, 9.1.2.4).");
        }
    }
}
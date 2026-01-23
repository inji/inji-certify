package io.mosip.certify.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties(prefix = "mosip.certify.data-provider-plugin.velocity-template")
@Configuration
@Data
public class VelocityEnvConfig {

    private Map<String, Integer> envConfigs = new HashMap<>();
}

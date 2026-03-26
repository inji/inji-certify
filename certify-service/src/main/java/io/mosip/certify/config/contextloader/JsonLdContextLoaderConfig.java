package io.mosip.certify.config.contextloader;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(JsonLdContextLoaderProperties.class)
public class JsonLdContextLoaderConfig {}

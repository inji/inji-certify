package io.mosip.certify.utils;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.cache.CacheManager;

import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CredentialCacheKeyGeneratorTest {

    @Mock
    private CredentialConfigRepository credentialConfigRepository;

    @Mock
    private CacheManager cacheManager;

    @InjectMocks
    private CredentialCacheKeyGenerator generator;

    @Test
    public void should_returnNull_when_credentialConfigKeyIdIsNull() {
        assertNull(generator.generateKeyFromCredentialConfigKeyId(null));
    }

    @Test
    public void should_returnDefaultKey_when_configNotFound() {
        when(credentialConfigRepository.findByCredentialConfigKeyId("missing"))
                .thenReturn(Optional.empty());
        assertEquals("default-key", generator.generateKeyFromCredentialConfigKeyId("missing"));
    }

    @Test
    public void should_useFormatAndVct_when_formatIsSdJwt() {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialFormat(VCFormats.DC_SD_JWT);
        config.setSdJwtVct("MyVct");
        when(credentialConfigRepository.findByCredentialConfigKeyId("k"))
                .thenReturn(Optional.of(config));

        String key = generator.generateKeyFromCredentialConfigKeyId("k");
        assertEquals(VCFormats.DC_SD_JWT + "::" + "MyVct", key);
    }

    @Test
    public void should_useTypeContextFormat_when_formatIsLdp() {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialFormat(VCFormats.LDP_VC);
        config.setCredentialType("MockType");
        config.setContext("https://example.org/ctx");
        when(credentialConfigRepository.findByCredentialConfigKeyId("k"))
                .thenReturn(Optional.of(config));

        String key = generator.generateKeyFromCredentialConfigKeyId("k");
        assertEquals("MockType::https://example.org/ctx::" + VCFormats.LDP_VC, key);
    }
}

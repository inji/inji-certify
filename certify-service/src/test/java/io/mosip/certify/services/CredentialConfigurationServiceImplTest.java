package io.mosip.certify.services;

import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.CredentialConfigException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.attributes.ClaimsDisplayFieldsConfigs;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.CredentialConfigMapper;
import io.mosip.certify.validators.credentialconfigvalidators.LdpVcCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.MsoMdocCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.SdJwtCredentialConfigValidator;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class CredentialConfigurationServiceImplTest {

    @Mock
    private CredentialConfigRepository credentialConfigRepository;

    @Mock
    private CredentialConfigMapper credentialConfigMapper;

    @InjectMocks
    private CredentialConfigurationServiceImpl credentialConfigurationService;

    @Mock
    private CredentialConfigurationDTO credentialConfigurationDTO;

    @Mock
    private CredentialConfigurationDTOV2 credentialConfigurationDTOV2;

    @Mock
    private CredentialConfig credentialConfig;

    @Mock
    private MetaDataDisplayDTOV2 metaDataDisplayDTOV2;

    @Mock
    private MetaDataDisplayDTO metaDataDisplayDTO;

    @Mock
    MetaDataDisplayDTOV2.Logo logo2;

    @Mock
    MetaDataDisplayDTO.Logo logo;

    @Before
    public void setup() {
        Map<String, List<List<String>>> keyAliasMapper = new HashMap<>();
        keyAliasMapper.put("EdDSA", List.of(
                List.of("TEST2019", "TEST2019-REF")));
//        keyAliasMapper.put("RS256", List.of());

        MockitoAnnotations.openMocks(this);
        logo = new MetaDataDisplayDTO.Logo();
        logo.setUrl("https://logo.mosip.io");
        logo2 = new MetaDataDisplayDTOV2.Logo();
        logo2.setUri("https://logo2.mosip.io");
        metaDataDisplayDTOV2 = new MetaDataDisplayDTOV2();
        metaDataDisplayDTOV2.setLogo(logo2);
        metaDataDisplayDTO = new MetaDataDisplayDTO();
        metaDataDisplayDTO.setLogo(logo);
        credentialConfig = new CredentialConfig();
        String id = UUID.randomUUID().toString();
        credentialConfig.setConfigId(id);
        credentialConfig.setCredentialConfigKeyId("test-credential");
        credentialConfig.setStatus("active");
        credentialConfig.setVcTemplate("test_template");
        credentialConfig.setContext("https://www.w3.org/2018/credentials/v1");
        credentialConfig.setCredentialType("VerifiableCredential,TestVerifiableCredential");
        credentialConfig.setCredentialFormat("ldp_vc");
        credentialConfig.setDidUrl("did:web:test.github.io:test-env:test-folder");
        credentialConfig.setOrder(Arrays.asList("test1", "test2", "test3", "test4"));
        credentialConfig.setScope("test_vc_ldp");
        credentialConfig.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        credentialConfig.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));
        credentialConfig.setCredentialSubject(Map.of("name", new ClaimsDisplayFieldsConfigs(List.of(new ClaimsDisplayFieldsConfigs.Display("Full Name", "en")))));
        credentialConfig.setKeyManagerAppId("TEST2019");
        credentialConfig.setKeyManagerRefId("TEST2019-REF");
        credentialConfig.setSignatureCryptoSuite("Ed25519Signature2020");

        credentialConfigurationDTO = new CredentialConfigurationDTO();
        credentialConfigurationDTO.setCredentialConfigKeyId("test-credential");
        credentialConfigurationDTO.setMetaDataDisplay(List.of(metaDataDisplayDTO));
        credentialConfigurationDTO.setVcTemplate("test_template");
        credentialConfigurationDTO.setCredentialFormat("ldp_vc");
        credentialConfigurationDTO.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        credentialConfigurationDTO.setCredentialTypes(Arrays.asList("VerifiableCredential", "TestVerifiableCredential"));
        credentialConfigurationDTO.setSignatureCryptoSuite("Ed25519Signature2020");
        credentialConfigurationDTO.setKeyManagerAppId("TEST2019");
        credentialConfigurationDTO.setKeyManagerRefId("TEST2019-REF");
        credentialConfigurationDTO.setCredentialSubjectDefinition(Map.of("name", new CredentialSubjectParametersDTO(List.of(new CredentialSubjectParametersDTO.Display("Full Name", "en")))));

        credentialConfigurationDTOV2 = new CredentialConfigurationDTOV2();
        credentialConfigurationDTOV2.setCredentialConfigKeyId("test-credential");
        credentialConfigurationDTOV2.setMetaDataDisplay(List.of(metaDataDisplayDTOV2));
        credentialConfigurationDTOV2.setVcTemplate("test_template");
        credentialConfigurationDTOV2.setCredentialFormat("ldp_vc");
        credentialConfigurationDTOV2.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        credentialConfigurationDTOV2.setCredentialTypes(Arrays.asList("VerifiableCredential", "TestVerifiableCredential"));
        credentialConfigurationDTOV2.setSignatureCryptoSuite("Ed25519Signature2020");
        credentialConfigurationDTOV2.setKeyManagerAppId("TEST2019");
        credentialConfigurationDTOV2.setKeyManagerRefId("TEST2019-REF");
        credentialConfigurationDTOV2.setCredentialSubjectDefinition(Map.of("name", new CredentialSubjectParametersDTO(List.of(new CredentialSubjectParametersDTO.Display("Full Name", "en")))));

        ReflectionTestUtils.setField(credentialConfigurationService, "credentialIssuer", "http://example.com/");
        ReflectionTestUtils.setField(credentialConfigurationService, "authUrl", "http://auth.com");
        ReflectionTestUtils.setField(credentialConfigurationService, "servletPath", "v1/test");
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        ReflectionTestUtils.setField(credentialConfigurationService, "issuerDisplay", List.of(Map.of()));
        Map<String, List<String>> credentialSigningMap = new LinkedHashMap<>();
        credentialSigningMap.put("Ed25519Signature2020", List.of("EdDSA"));
        credentialSigningMap.put("RsaSignature2018", List.of("RS256"));
        ReflectionTestUtils.setField(credentialConfigurationService, "cryptographicBindingMethodsSupportedMap", new LinkedHashMap<>());
        ReflectionTestUtils.setField(credentialConfigurationService, "credentialSigningAlgValuesSupportedMap", credentialSigningMap);
        ReflectionTestUtils.setField(credentialConfigurationService, "proofTypesSupported", new LinkedHashMap<>());
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper", keyAliasMapper);
        Map<String, String> authServerMapping = new HashMap<>();
        authServerMapping.put("default", "http://auth.com");
        ReflectionTestUtils.setField(credentialConfigurationService, "authorizationServerMapping", authServerMapping);

    }

    @Test
    public void addNewCredentialConfig_Success() {
        credentialConfigurationDTO.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        credentialConfigurationDTO.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        credentialConfigurationDTO.setSignatureCryptoSuite("Ed25519Signature2020");
        credentialConfigurationDTO.setSignatureAlgo("EdDSA");
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(credentialConfig);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(credentialConfig);

        CredentialConfigResponse credentialConfigResponse = credentialConfigurationService.addCredentialConfiguration(credentialConfigurationDTO);

        Assert.assertNotNull(credentialConfigResponse);
        Assert.assertNotNull(credentialConfigResponse.getId());
        Assert.assertNotNull(credentialConfigResponse.getStatus());
        Assert.assertEquals("active", credentialConfigResponse.getStatus());
    }

    @Test
    public void addNewCredentialConfig_SuccessV2() {
        credentialConfigurationDTOV2.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        credentialConfigurationDTOV2.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        credentialConfigurationDTOV2.setSignatureCryptoSuite("Ed25519Signature2020");
        credentialConfigurationDTOV2.setSignatureAlgo("EdDSA");
        when(credentialConfigMapper.toEntityV2(any(CredentialConfigurationDTOV2.class))).thenReturn(credentialConfig);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(credentialConfig);

        CredentialConfigResponse credentialConfigResponse = credentialConfigurationService.addCredentialConfigurationV2(credentialConfigurationDTOV2);

        Assert.assertNotNull(credentialConfigResponse);
        Assert.assertNotNull(credentialConfigResponse.getId());
        Assert.assertNotNull(credentialConfigResponse.getStatus());
        Assert.assertEquals("active", credentialConfigResponse.getStatus());
    }

    @Test
    public void addCredentialConfiguration_DataProviderMode_VcTemplateNull_ThrowsException() {
        // Arrange
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(null); // or ""

        // Act & Assert
        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.addCredentialConfiguration(dto)
        );
        org.junit.Assert.assertEquals("A Credential Template is required for issuers using the Data Provider plugin.", exception.getMessage());
    }

    @Test
    public void addCredentialConfigurationV2_DataProviderMode_VcTemplateNull_ThrowsException() {
        // Arrange
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(null); // or ""

        // Act & Assert
        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.addCredentialConfigurationV2(dto)
        );
        org.junit.Assert.assertEquals("A Credential Template is required for issuers using the Data Provider plugin.", exception.getMessage());
    }

    @Test
    public void getCredentialConfigById_Success() {
        Optional<CredentialConfig> optional = Optional.of(credentialConfig);
        when(credentialConfigRepository.findByCredentialConfigKeyId(anyString())).thenReturn(optional);
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(credentialConfigurationDTO);
        CredentialConfigurationDTO credentialConfigurationDTOResponse = credentialConfigurationService.getCredentialConfigurationById("test");

        Assert.assertNotNull(credentialConfigurationDTOResponse);
        Assert.assertNotNull(credentialConfigurationDTOResponse.getCredentialTypes());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getCredentialFormat());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getContextURLs());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getVcTemplate());
        Assert.assertEquals("test_template", credentialConfigurationDTOResponse.getVcTemplate());
        Assert.assertEquals(List.of("https://www.w3.org/2018/credentials/v1"), credentialConfigurationDTOResponse.getContextURLs());
        Assert.assertEquals(Arrays.asList("VerifiableCredential", "TestVerifiableCredential"), credentialConfigurationDTOResponse.getCredentialTypes());
        Assert.assertEquals("ldp_vc", credentialConfigurationDTOResponse.getCredentialFormat());
    }

    @Test
    public void getCredentialConfigByIdV2_Success() {
        Optional<CredentialConfig> optional = Optional.of(credentialConfig);
        when(credentialConfigRepository.findByCredentialConfigKeyId(anyString())).thenReturn(optional);
        when(credentialConfigMapper.toDtoV2(any(CredentialConfig.class))).thenReturn(credentialConfigurationDTOV2);
        CredentialConfigurationDTOV2 credentialConfigurationDTOResponse = credentialConfigurationService.getCredentialConfigurationByIdV2("test");

        Assert.assertNotNull(credentialConfigurationDTOResponse);
        Assert.assertNotNull(credentialConfigurationDTOResponse.getCredentialTypes());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getCredentialFormat());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getContextURLs());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getVcTemplate());
        Assert.assertEquals("test_template", credentialConfigurationDTOResponse.getVcTemplate());
        Assert.assertEquals(List.of("https://www.w3.org/2018/credentials/v1"), credentialConfigurationDTOResponse.getContextURLs());
        Assert.assertEquals(Arrays.asList("VerifiableCredential", "TestVerifiableCredential"), credentialConfigurationDTOResponse.getCredentialTypes());
        Assert.assertEquals("ldp_vc", credentialConfigurationDTOResponse.getCredentialFormat());
    }

    @Test
    public void getCredentialConfigurationById_ConfigNotFound() {
        when(credentialConfigRepository.findByCredentialConfigKeyId("12345678"))
                .thenReturn(Optional.empty());

        CredentialConfigException exception = assertThrows(CredentialConfigException.class, () ->
                credentialConfigurationService.getCredentialConfigurationById("12345678"));

        assertEquals("Configuration not found for the provided ID: 12345678", exception.getMessage());
    }

    @Test
    public void getCredentialConfigurationByIdV2_ConfigNotFound() {
        when(credentialConfigRepository.findByCredentialConfigKeyId("12345678"))
                .thenReturn(Optional.empty());

        CredentialConfigException exception = assertThrows(CredentialConfigException.class, () ->
                credentialConfigurationService.getCredentialConfigurationByIdV2("12345678"));

        assertEquals("Configuration not found for the provided ID: 12345678", exception.getMessage());
    }

    @Test
    public void getCredentialConfigurationById_ConfigNotActive_ThrowsException() {
        CredentialConfig inactiveConfig = new CredentialConfig();
        inactiveConfig.setStatus("inactive"); // Not Constants.ACTIVE
        when(credentialConfigRepository.findByCredentialConfigKeyId(anyString())).thenReturn(Optional.of(inactiveConfig));
        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.getCredentialConfigurationById("test-id")
        );
        assertEquals("Configuration is inactive.", exception.getMessage());
    }

    @Test
    public void getCredentialConfigurationByIdV2_ConfigNotActive_ThrowsException() {
        CredentialConfig inactiveConfig = new CredentialConfig();
        inactiveConfig.setStatus("inactive"); // Not Constants.ACTIVE
        when(credentialConfigRepository.findByCredentialConfigKeyId(anyString())).thenReturn(Optional.of(inactiveConfig));
        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.getCredentialConfigurationByIdV2("test-id")
        );
        assertEquals("Configuration is inactive.", exception.getMessage());
    }

    @Test
    public void updateExistingCredentialConfig_Success() {
        CredentialConfig mockCredentialConfig = new CredentialConfig();
        String expectedId = "test-credential";
        String expectedStatus = "active";
        mockCredentialConfig.setConfigId("12345678");
        mockCredentialConfig.setCredentialConfigKeyId("test-credential");
        mockCredentialConfig.setStatus(expectedStatus);
        mockCredentialConfig.setVcTemplate("some_template");
        mockCredentialConfig.setCredentialFormat("vc+sd-jwt");
        mockCredentialConfig.setSdJwtVct("test-vct");
        mockCredentialConfig.setSignatureAlgo("ES256");


        Optional<CredentialConfig> optionalConfig = Optional.of(mockCredentialConfig);
        when(credentialConfigRepository.findByCredentialConfigKeyId(eq(expectedId))).thenReturn(optionalConfig);


        CredentialConfigurationDTO mockDto = new CredentialConfigurationDTO();

        // Create a valid DTO for validation that will be returned by toDto
        CredentialConfigurationDTO validationDto = new CredentialConfigurationDTO();
        validationDto.setCredentialFormat("vc+sd-jwt");
        validationDto.setVcTemplate("some_template");
        validationDto.setSdJwtVct("test-vct");
        validationDto.setSignatureAlgo("ES256");
        validationDto.setCredentialConfigKeyId("test-credential");
        validationDto.setCredentialStatusPurposes(null); // Ensure this is not null to avoid NPE

        // Mock the mapper methods
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(validationDto);
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(mockCredentialConfig);

        // --- Act ---
        CredentialConfigResponse credentialConfigResponse = credentialConfigurationService.updateCredentialConfiguration(expectedId, mockDto);

        // --- Assert ---
        Assert.assertNotNull(credentialConfigResponse);
        Assert.assertNotNull(credentialConfigResponse.getId());
        Assert.assertNotNull(credentialConfigResponse.getStatus());

        Assert.assertEquals(expectedId, credentialConfigResponse.getId());
        Assert.assertEquals(expectedStatus, credentialConfigResponse.getStatus());

        // Verify interactions
        verify(credentialConfigRepository).findByCredentialConfigKeyId(eq(expectedId));
        verify(credentialConfigMapper).updateEntityFromDto(eq(mockDto), eq(mockCredentialConfig));
        verify(credentialConfigRepository).save(eq(mockCredentialConfig));
    }

    @Test
    public void updateExistingCredentialConfigV2_Success() {
        CredentialConfig mockCredentialConfig = new CredentialConfig();
        String expectedId = "test-credential";
        String expectedStatus = "active";
        mockCredentialConfig.setConfigId("12345678");
        mockCredentialConfig.setCredentialConfigKeyId("test-credential");
        mockCredentialConfig.setStatus(expectedStatus);
        mockCredentialConfig.setVcTemplate("some_template");
        mockCredentialConfig.setCredentialFormat("vc+sd-jwt");
        mockCredentialConfig.setSdJwtVct("test-vct");
        mockCredentialConfig.setSignatureAlgo("ES256");


        Optional<CredentialConfig> optionalConfig = Optional.of(mockCredentialConfig);
        when(credentialConfigRepository.findByCredentialConfigKeyId(eq(expectedId))).thenReturn(optionalConfig);


        CredentialConfigurationDTOV2 mockDto = new CredentialConfigurationDTOV2();

        // Create a valid DTO for validation that will be returned by toDto
        CredentialConfigurationDTOV2 validationDto = new CredentialConfigurationDTOV2();
        validationDto.setCredentialFormat("vc+sd-jwt");
        validationDto.setVcTemplate("some_template");
        validationDto.setSdJwtVct("test-vct");
        validationDto.setSignatureAlgo("ES256");
        validationDto.setCredentialConfigKeyId("test-credential");
        validationDto.setCredentialStatusPurposes(null); // Ensure this is not null to avoid NPE

        // Mock the mapper methods
        when(credentialConfigMapper.toDtoV2(any(CredentialConfig.class))).thenReturn(validationDto);
        doNothing().when(credentialConfigMapper).updateEntityFromDtoV2(any(CredentialConfigurationDTOV2.class), any(CredentialConfig.class));
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(mockCredentialConfig);

        // --- Act ---
        CredentialConfigResponse credentialConfigResponse = credentialConfigurationService.updateCredentialConfigurationV2(expectedId, mockDto);

        // --- Assert ---
        Assert.assertNotNull(credentialConfigResponse);
        Assert.assertNotNull(credentialConfigResponse.getId());
        Assert.assertNotNull(credentialConfigResponse.getStatus());

        Assert.assertEquals(expectedId, credentialConfigResponse.getId());
        Assert.assertEquals(expectedStatus, credentialConfigResponse.getStatus());

        // Verify interactions
        verify(credentialConfigRepository).findByCredentialConfigKeyId(eq(expectedId));
        verify(credentialConfigMapper).updateEntityFromDtoV2(eq(mockDto), eq(mockCredentialConfig));
        verify(credentialConfigRepository).save(eq(mockCredentialConfig));
    }

    @Test
    public void updateExistingCredentialConfiguration_ConfigNotFound() {
        when(credentialConfigRepository.findByCredentialConfigKeyId(anyString()))
                .thenReturn(Optional.empty());

        CredentialConfigException exception = assertThrows(CredentialConfigException.class, () ->
                credentialConfigurationService.updateCredentialConfiguration("12345678", new CredentialConfigurationDTO()));

        assertEquals("Configuration not found for update with ID: 12345678", exception.getMessage());
    }

    @Test
    public void updateExistingCredentialConfigurationV2_ConfigNotFound() {
        when(credentialConfigRepository.findByCredentialConfigKeyId(anyString()))
                .thenReturn(Optional.empty());

        CredentialConfigException exception = assertThrows(CredentialConfigException.class, () ->
                credentialConfigurationService.updateCredentialConfigurationV2("12345678", new CredentialConfigurationDTOV2()));

        assertEquals("Configuration not found for update with ID: 12345678", exception.getMessage());
    }

    @Test
    public void deleteCredentialConfig_Success() {
        Optional<CredentialConfig> optional = Optional.of(credentialConfig);
        when(credentialConfigRepository.findByCredentialConfigKeyId(anyString())).thenReturn(optional);
        doNothing().when(credentialConfigRepository).delete(any(CredentialConfig.class));
        String result = credentialConfigurationService.deleteCredentialConfigurationById("12345678");

        Assert.assertNotNull(result);
        assertEquals("12345678", result);
    }

    @Test
    public void deleteCredentialConfiguration_ConfigNotFound() {
        when(credentialConfigRepository.findByCredentialConfigKeyId(anyString()))
                .thenReturn(Optional.empty());

        CredentialConfigException exception = assertThrows(CredentialConfigException.class, () ->
                credentialConfigurationService.deleteCredentialConfigurationById("12345678"));

        assertEquals("Configuration not found for delete with ID: 12345678", exception.getMessage());
    }

    @Test
    public void fetchCredentialIssuerMetadata_Success() {
        // Setup test data
        List<CredentialConfig> credentialConfigList = List.of(credentialConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(credentialConfigurationDTO);

        // Call the method
        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        // Verify results
        Assert.assertNotNull(result);
        Assert.assertEquals("http://example.com/", result.getCredentialIssuer());
        Assert.assertEquals(List.of("http://auth.com"), result.getAuthorizationServers());
        Assert.assertEquals("http://example.com/v1/test/issuance/credential", result.getCredentialEndpoint());

        // Verify credential configuration
        Assert.assertNotNull(result.getCredentialConfigurationSupportedDTO());
        Assert.assertEquals(1, result.getCredentialConfigurationSupportedDTO().size());
        Assert.assertTrue(result.getCredentialConfigurationSupportedDTO().containsKey("test-credential"));

        // Verify mapping was called
        verify(credentialConfigRepository).findAll();
        verify(credentialConfigMapper).toDto(credentialConfig);
    }

    @Test
    public void fetchCredentialIssuerMetadataV2_Success() {
        // Setup test data
        List<CredentialConfig> credentialConfigList = List.of(credentialConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);
        when(credentialConfigMapper.toDtoV2(any(CredentialConfig.class))).thenReturn(credentialConfigurationDTOV2);

        // Call the method
        CredentialIssuerMetadataDTOV2 result = credentialConfigurationService.fetchCredentialIssuerMetadataV2("latest");

        // Verify results
        Assert.assertNotNull(result);
        Assert.assertEquals("http://example.com/", result.getCredentialIssuer());
        Assert.assertEquals(List.of("http://auth.com"), result.getAuthorizationServers());
        Assert.assertEquals("http://example.com/v1/test/issuance/credential", result.getCredentialEndpoint());

        // Verify credential configuration
        Assert.assertNotNull(result.getCredentialConfigurationSupportedDTOV2());
        Assert.assertEquals(1, result.getCredentialConfigurationSupportedDTOV2().size());
        Assert.assertTrue(result.getCredentialConfigurationSupportedDTOV2().containsKey("test-credential"));

        // Verify mapping was called
        verify(credentialConfigRepository).findAll();
        verify(credentialConfigMapper).toDtoV2(credentialConfig);
    }

    @Test
    public void fetchCredentialIssuerMetadata_SigningAlgValuesSupported_UsesSignatureAlgo_WhenCryptoSuiteIsNull() {
        CredentialConfig config = new CredentialConfig();
        config.setConfigId(UUID.randomUUID().toString());
        config.setCredentialConfigKeyId("test-credential");
        config.setStatus("active");
        config.setCredentialFormat("ldp_vc");
        config.setSignatureCryptoSuite(null); // triggers else branch
        config.setSignatureAlgo("ES256");
        config.setCredentialSubject(null);

        when(credentialConfigRepository.findAll()).thenReturn(List.of(config));
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        when(credentialConfigMapper.toDto(config)).thenReturn(dto);


        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        Assert.assertNotNull(result);
        Assert.assertTrue(result.getCredentialConfigurationSupportedDTO().containsKey("test-credential"));
        CredentialConfigurationSupportedDTO supportedDTO = result.getCredentialConfigurationSupportedDTO().get("test-credential");
        Assert.assertEquals(List.of("ES256"), supportedDTO.getCredentialSigningAlgValuesSupported());
    }

    @Test
    public void fetchCredentialIssuerMetadataV2_SigningAlgValuesSupported_UsesSignatureAlgo_WhenCryptoSuiteIsNull() {
        CredentialConfig config = new CredentialConfig();
        config.setConfigId(UUID.randomUUID().toString());
        config.setCredentialConfigKeyId("test-credential");
        config.setStatus("active");
        config.setCredentialFormat("ldp_vc");
        config.setSignatureCryptoSuite(null); // triggers else branch
        config.setSignatureAlgo("ES256");
        config.setCredentialSubject(null);

        when(credentialConfigRepository.findAll()).thenReturn(List.of(config));
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc");
        when(credentialConfigMapper.toDtoV2(config)).thenReturn(dto);


        CredentialIssuerMetadataDTOV2 result = credentialConfigurationService.fetchCredentialIssuerMetadataV2("latest");

        Assert.assertNotNull(result);
        Assert.assertTrue(result.getCredentialConfigurationSupportedDTOV2().containsKey("test-credential"));
        CredentialConfigurationSupportedDTOV2 supportedDTO = result.getCredentialConfigurationSupportedDTOV2().get("test-credential");
        Assert.assertEquals(List.of("ES256"), supportedDTO.getCredentialSigningAlgValuesSupported());
    }

    @Test
    public void fetchCredentialIssuerMetadata_SigningAlgValuesSupported_UsesSignatureAlgo_WhenCryptoSuiteIsNull_SdJwtFormat() {
        CredentialConfig config = new CredentialConfig();
        config.setConfigId(UUID.randomUUID().toString());
        config.setCredentialConfigKeyId("sdjwt-credential");
        config.setStatus("active");
        config.setCredentialFormat("vc+sd-jwt");
        config.setSignatureCryptoSuite(null); // triggers else branch
        config.setSignatureAlgo("ES256");
        config.setSdJwtVct("test-vct");

        when(credentialConfigRepository.findAll()).thenReturn(List.of(config));
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("vc+sd-jwt");
        when(credentialConfigMapper.toDto(config)).thenReturn(dto);

        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        Assert.assertNotNull(result);
        Assert.assertTrue(result.getCredentialConfigurationSupportedDTO().containsKey("sdjwt-credential"));
        CredentialConfigurationSupportedDTO supportedDTO = result.getCredentialConfigurationSupportedDTO().get("sdjwt-credential");
        Assert.assertEquals(List.of("ES256"), supportedDTO.getCredentialSigningAlgValuesSupported());
    }

    @Test
    public void fetchCredentialIssuerMetadataV2_SigningAlgValuesSupported_UsesSignatureAlgo_WhenCryptoSuiteIsNull_SdJwtFormat() {
        CredentialConfig config = new CredentialConfig();
        config.setConfigId(UUID.randomUUID().toString());
        config.setCredentialConfigKeyId("sdjwt-credential");
        config.setStatus("active");
        config.setCredentialFormat("vc+sd-jwt");
        config.setSignatureCryptoSuite(null); // triggers else branch
        config.setSignatureAlgo("ES256");
        config.setSdJwtVct("test-vct");

        when(credentialConfigRepository.findAll()).thenReturn(List.of(config));
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("vc+sd-jwt");
        when(credentialConfigMapper.toDtoV2(config)).thenReturn(dto);

        CredentialIssuerMetadataDTOV2 result = credentialConfigurationService.fetchCredentialIssuerMetadataV2("latest");

        Assert.assertNotNull(result);
        Assert.assertTrue(result.getCredentialConfigurationSupportedDTOV2().containsKey("sdjwt-credential"));
        CredentialConfigurationSupportedDTOV2 supportedDTO = result.getCredentialConfigurationSupportedDTOV2().get("sdjwt-credential");
        Assert.assertEquals(List.of("ES256"), supportedDTO.getCredentialSigningAlgValuesSupported());
    }

    @Test
    public void fetchCredentialIssuerMetadata_vd11Version() {
        // Setup minimal test data
        List<CredentialConfig> credentialConfigList = List.of(credentialConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(credentialConfigurationDTO);

        // Call with specific version
        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("vd11");

        // Verify version in endpoint
        Assert.assertEquals("http://example.com/v1/test/issuance/vd11/credential", result.getCredentialEndpoint());
    }

    @Test
    public void fetchCredentialIssuerMetadataV2_vd11Version() {
        // Setup minimal test data
        List<CredentialConfig> credentialConfigList = List.of(credentialConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);
        when(credentialConfigMapper.toDtoV2(any(CredentialConfig.class))).thenReturn(credentialConfigurationDTOV2);

        // Call with specific version
        CredentialIssuerMetadataDTOV2 result = credentialConfigurationService.fetchCredentialIssuerMetadataV2("vd11");

        // Verify version in endpoint
        Assert.assertEquals("http://example.com/v1/test/issuance/vd11/credential", result.getCredentialEndpoint());
    }

    @Test
    public void fetchCredentialIssuerMetadata_vd12Version() {
        // Setup minimal test data
        List<CredentialConfig> credentialConfigList = List.of(credentialConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(credentialConfigurationDTO);

        // Call with specific version
        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("vd12");

        // Verify version in endpoint
        Assert.assertEquals("http://example.com/v1/test/issuance/vd12/credential", result.getCredentialEndpoint());
    }

    @Test
    public void fetchCredentialIssuerMetadataV2_vd12Version() {
        // Setup minimal test data
        List<CredentialConfig> credentialConfigList = List.of(credentialConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);
        when(credentialConfigMapper.toDtoV2(any(CredentialConfig.class))).thenReturn(credentialConfigurationDTOV2);

        // Call with specific version
        CredentialIssuerMetadataDTOV2 result = credentialConfigurationService.fetchCredentialIssuerMetadataV2("vd12");

        // Verify version in endpoint
        Assert.assertEquals("http://example.com/v1/test/issuance/vd12/credential", result.getCredentialEndpoint());
    }

    @Test
    public void fetchCredentialIssuerMetadata_invalidVersion() {
        // Setup minimal test data
        List<CredentialConfig> credentialConfigList = List.of(credentialConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);

        // Call with specific version

        CertifyException ex = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.fetchCredentialIssuerMetadata("unsupported_version")
        );
        assertEquals("Unsupported version: unsupported_version", ex.getMessage());
    }

    @Test
    public void fetchCredentialIssuerMetadataV2_invalidVersion() {
        // Setup minimal test data
        List<CredentialConfig> credentialConfigList = List.of(credentialConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);

        // Call with specific version

        CertifyException ex = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.fetchCredentialIssuerMetadataV2("unsupported_version")
        );
        assertEquals("Unsupported version: unsupported_version", ex.getMessage());
    }

    @Test
    public void fetchCredentialIssuerMetadata_EmptyCredentialConfigs() {
        // Setup empty credential config list
        when(credentialConfigRepository.findAll()).thenReturn(Collections.emptyList());

        // Call the method
        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        // Verify core metadata still populated
        Assert.assertNotNull(result);
        Assert.assertEquals("http://example.com/", result.getCredentialIssuer());
        Assert.assertEquals(List.of("http://auth.com"), result.getAuthorizationServers());

        // Verify empty configurations map
        Assert.assertNotNull(result.getCredentialConfigurationSupportedDTO());
        Assert.assertTrue(result.getCredentialConfigurationSupportedDTO().isEmpty());

        // Verify no mapping calls
        verify(credentialConfigRepository).findAll();
        verify(credentialConfigMapper, never()).toDto((CredentialConfig) any());
    }

    @Test
    public void fetchCredentialIssuerMetadataV2_EmptyCredentialConfigs() {
        // Setup empty credential config list
        when(credentialConfigRepository.findAll()).thenReturn(Collections.emptyList());

        // Call the method
        CredentialIssuerMetadataDTOV2 result = credentialConfigurationService.fetchCredentialIssuerMetadataV2("latest");

        // Verify core metadata still populated
        Assert.assertNotNull(result);
        Assert.assertEquals("http://example.com/", result.getCredentialIssuer());
        Assert.assertEquals(List.of("http://auth.com"), result.getAuthorizationServers());

        // Verify empty configurations map
        Assert.assertNotNull(result.getCredentialConfigurationSupportedDTOV2());
        Assert.assertTrue(result.getCredentialConfigurationSupportedDTOV2().isEmpty());

        // Verify no mapping calls
        verify(credentialConfigRepository).findAll();
        verify(credentialConfigMapper, never()).toDtoV2(any());
    }

    @Test
    public void fetchCredentialIssuerMetadata_MsoMdocFormat() {
        // Setup CredentialConfig with MSO_MDOC format
        CredentialConfig mdocConfig = new CredentialConfig();
        mdocConfig.setConfigId(UUID.randomUUID().toString());
        mdocConfig.setCredentialConfigKeyId("mdoc-credential");

        mdocConfig.setStatus("active");
        mdocConfig.setCredentialFormat("mso_mdoc");
        mdocConfig.setMsoMdocClaims(Map.of("firstName", Map.of( "First Name", new ClaimsDisplayFieldsConfigs(List.of(new ClaimsDisplayFieldsConfigs.Display("Test","en"))))));
        mdocConfig.setDocType("docType1");

        List<CredentialConfig> credentialConfigList = List.of(mdocConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);

        // Setup DTO for MSO_MDOC
        CredentialConfigurationDTO mdocDTO = new CredentialConfigurationDTO();
        mdocDTO.setCredentialFormat("mso_mdoc");
        mdocDTO.setCredentialConfigKeyId("mdoc-credential");
        mdocDTO.setScope("mdoc_scope");
        mdocDTO.setMsoMdocClaims(Map.of("firstName", Map.of( "First Name", new ClaimsDisplayFieldsConfigDTO(List.of(new ClaimsDisplayFieldsConfigDTO.Display("Test","en"))))));
        mdocDTO.setDocType("docType1");

        when(credentialConfigMapper.toDto(mdocConfig)).thenReturn(mdocDTO);

        // Call the method
        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        // Verify MSO_MDOC configuration
        Assert.assertNotNull(result.getCredentialConfigurationSupportedDTO());
        Assert.assertEquals(1, result.getCredentialConfigurationSupportedDTO().size());
        Assert.assertEquals(Map.of("firstName", Map.of( "First Name", new ClaimsDisplayFieldsConfigs(List.of(new ClaimsDisplayFieldsConfigs.Display("Test","en"))))), result.getCredentialConfigurationSupportedDTO().get("mdoc-credential").getClaims());

        CredentialConfigurationSupportedDTO supportedDTO = result.getCredentialConfigurationSupportedDTO().get("mdoc-credential");
        Assert.assertNotNull(supportedDTO);
        Assert.assertEquals("mso_mdoc", supportedDTO.getFormat());
        Assert.assertNotNull(supportedDTO.getClaims());
        Assert.assertEquals("docType1", supportedDTO.getDocType());
        Assert.assertNull(supportedDTO.getCredentialDefinition());
    }

    @Test
    public void fetchCredentialIssuerMetadataV2_MsoMdocFormat() {
        // Setup CredentialConfig with MSO_MDOC format
        CredentialConfig mdocConfig = new CredentialConfig();
        mdocConfig.setConfigId(UUID.randomUUID().toString());
        mdocConfig.setCredentialConfigKeyId("mdoc-credential");

        mdocConfig.setStatus("active");
        mdocConfig.setCredentialFormat("mso_mdoc");
        mdocConfig.setMsoMdocClaims(Map.of("firstName", Map.of( "First Name", new ClaimsDisplayFieldsConfigs(List.of(new ClaimsDisplayFieldsConfigs.Display("Test","en"))))));
        mdocConfig.setDocType("docType1");

        List<CredentialConfig> credentialConfigList = List.of(mdocConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);

        // Setup DTO for MSO_MDOC
        CredentialConfigurationDTOV2 mdocDTO = new CredentialConfigurationDTOV2();
        mdocDTO.setCredentialFormat("mso_mdoc");
        mdocDTO.setCredentialConfigKeyId("mdoc-credential");
        mdocDTO.setScope("mdoc_scope");
        mdocDTO.setMsoMdocClaims(Map.of("firstName", Map.of( "First Name", new ClaimsDisplayFieldsConfigDTO(List.of(new ClaimsDisplayFieldsConfigDTO.Display("Test","en"))))));
        mdocDTO.setDocType("docType1");

        when(credentialConfigMapper.toDtoV2(mdocConfig)).thenReturn(mdocDTO);

        // Call the method
        CredentialIssuerMetadataDTOV2 result = credentialConfigurationService.fetchCredentialIssuerMetadataV2("latest");

        // Verify MSO_MDOC configuration
        Assert.assertNotNull(result.getCredentialConfigurationSupportedDTOV2());
        Assert.assertEquals(1, result.getCredentialConfigurationSupportedDTOV2().size());

        CredentialConfigurationSupportedDTOV2 supportedDTO = result.getCredentialConfigurationSupportedDTOV2().get("mdoc-credential");
        Assert.assertNotNull(supportedDTO);
        Assert.assertEquals("mso_mdoc", supportedDTO.getFormat());
        Assert.assertNotNull(supportedDTO.getCredentialMetadata());
        Assert.assertNotNull(supportedDTO.getCredentialMetadata().getClaims());
        Assert.assertEquals(1, supportedDTO.getCredentialMetadata().getClaims().size());
        Assert.assertEquals("docType1", supportedDTO.getDocType());
    }

    // Add these methods to CredentialConfigurationServiceImplTest

    @Test
    public void addNewCredentialConfig_MsoMdoc_Success(){
        CredentialConfig mdocConfig = new CredentialConfig();
        mdocConfig.setConfigId(UUID.randomUUID().toString());
        mdocConfig.setCredentialConfigKeyId("mdoc-credential");
        mdocConfig.setStatus("active");
        mdocConfig.setVcTemplate("mdoc_template");
        mdocConfig.setCredentialFormat("mso_mdoc");
        mdocConfig.setDocType("docType1");
        mdocConfig.setSignatureCryptoSuite("Ed25519Signature2020");

        CredentialConfigurationDTO mdocDTO = new CredentialConfigurationDTO();
        mdocDTO.setCredentialFormat("mso_mdoc");
        mdocDTO.setCredentialConfigKeyId("mdoc-credential");
        mdocDTO.setDocType("docType1");
        mdocDTO.setVcTemplate("mdoc_template");
        mdocDTO.setSignatureCryptoSuite("Ed25519Signature2020"); // required

        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(mdocConfig);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(mdocConfig);

        CredentialConfigResponse response = credentialConfigurationService.addCredentialConfiguration(mdocDTO);

        Assert.assertNotNull(response);
        Assert.assertEquals("active", response.getStatus());
        Assert.assertEquals(mdocConfig.getCredentialConfigKeyId(), response.getId());
    }

    @Test
    public void addNewCredentialConfigV2_MsoMdoc_Success(){
        CredentialConfig mdocConfig = new CredentialConfig();
        mdocConfig.setConfigId(UUID.randomUUID().toString());
        mdocConfig.setCredentialConfigKeyId("mdoc-credential");
        mdocConfig.setStatus("active");
        mdocConfig.setVcTemplate("mdoc_template");
        mdocConfig.setCredentialFormat("mso_mdoc");
        mdocConfig.setDocType("docType1");
        mdocConfig.setSignatureCryptoSuite("Ed25519Signature2020");

        CredentialConfigurationDTOV2 mdocDTO = new CredentialConfigurationDTOV2();
        mdocDTO.setCredentialFormat("mso_mdoc");
        mdocDTO.setCredentialConfigKeyId("mdoc-credential");
        mdocDTO.setDocType("docType1");
        mdocDTO.setVcTemplate("mdoc_template");
        mdocDTO.setSignatureCryptoSuite("Ed25519Signature2020"); // required

        when(credentialConfigMapper.toEntityV2(any(CredentialConfigurationDTOV2.class))).thenReturn(mdocConfig);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(mdocConfig);

        CredentialConfigResponse response = credentialConfigurationService.addCredentialConfigurationV2(mdocDTO);

        Assert.assertNotNull(response);
        Assert.assertEquals("active", response.getStatus());
        Assert.assertEquals(mdocConfig.getCredentialConfigKeyId(), response.getId());
    }

    @Test
    public void addNewCredentialConfig_SdJwt_Success() {
        CredentialConfig sdJwtConfig = new CredentialConfig();
        sdJwtConfig.setConfigId(UUID.randomUUID().toString());
        sdJwtConfig.setCredentialConfigKeyId("sdjwt-credential");
        sdJwtConfig.setVcTemplate("sd_jwt_template");
        sdJwtConfig.setStatus("active");
        sdJwtConfig.setCredentialFormat("vc+sd-jwt");
        sdJwtConfig.setSdJwtVct("test-vct");
        sdJwtConfig.setSignatureAlgo("ES256");

        CredentialConfigurationDTO sdJwtDTO = new CredentialConfigurationDTO();
        sdJwtDTO.setCredentialFormat("vc+sd-jwt");
        sdJwtDTO.setCredentialConfigKeyId("sdjwt-credential");
        sdJwtDTO.setVcTemplate("sd_jwt_template");
        sdJwtDTO.setSdJwtVct("test-vct"); // required
        sdJwtDTO.setSignatureAlgo("ES256"); // required

        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(sdJwtConfig);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(sdJwtConfig);


        CredentialConfigResponse response = credentialConfigurationService.addCredentialConfiguration(sdJwtDTO);

        Assert.assertNotNull(response);
        Assert.assertEquals("active", response.getStatus());
        Assert.assertEquals(sdJwtConfig.getCredentialConfigKeyId(), response.getId());
    }

    @Test
    public void addNewCredentialConfigV2_SdJwt_Success() {
        CredentialConfig sdJwtConfig = new CredentialConfig();
        sdJwtConfig.setConfigId(UUID.randomUUID().toString());
        sdJwtConfig.setCredentialConfigKeyId("sdjwt-credential");
        sdJwtConfig.setVcTemplate("sd_jwt_template");
        sdJwtConfig.setStatus("active");
        sdJwtConfig.setCredentialFormat("vc+sd-jwt");
        sdJwtConfig.setSdJwtVct("test-vct");
        sdJwtConfig.setSignatureAlgo("ES256");

        CredentialConfigurationDTOV2 sdJwtDTO = new CredentialConfigurationDTOV2();
        sdJwtDTO.setCredentialFormat("vc+sd-jwt");
        sdJwtDTO.setCredentialConfigKeyId("sdjwt-credential");
        sdJwtDTO.setVcTemplate("sd_jwt_template");
        sdJwtDTO.setSdJwtVct("test-vct"); // required
        sdJwtDTO.setSignatureAlgo("ES256"); // required

        when(credentialConfigMapper.toEntityV2(any(CredentialConfigurationDTOV2.class))).thenReturn(sdJwtConfig);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(sdJwtConfig);


        CredentialConfigResponse response = credentialConfigurationService.addCredentialConfigurationV2(sdJwtDTO);

        Assert.assertNotNull(response);
        Assert.assertEquals("active", response.getStatus());
        Assert.assertEquals(sdJwtConfig.getCredentialConfigKeyId(), response.getId());
    }

    @Test
    public void validateCredentialConfiguration_LdpVc_Invalid_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(dto)).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
            );
            assertEquals("Fields context, credentialType, and signatureCryptoSuite are mandatory for the ldp_vc format.", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfigurationV2_LdpVc_Invalid_ThrowsException() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheckV2(dto)).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true)
            );
            assertEquals("Fields context, credentialType, and signatureCryptoSuite are mandatory for the ldp_vc format.", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_LdpVc_Duplicate_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            mocked.when(() -> LdpVcCredentialConfigValidator.isConfigAlreadyPresent(eq(dto), any())).thenReturn(true);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
            );
            assertEquals("Configuration already exists for the specified context and credentialType.", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfigurationV2_LdpVc_Duplicate_ThrowsException() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheckV2(dto)).thenReturn(true);
            mocked.when(() -> LdpVcCredentialConfigValidator.isConfigAlreadyPresentV2(eq(dto), any())).thenReturn(true);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true)
            );
            assertEquals("Configuration already exists for the specified context and credentialType.", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_MsoMdoc_Invalid_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("mso_mdoc");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(MsoMdocCredentialConfigValidator.class)) {
            mocked.when(() -> MsoMdocCredentialConfigValidator.isValidCheck(dto)).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
            );
            assertEquals("Fields doctype and signatureCryptoSuite are mandatory for the mso_mdoc format.", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfigurationV2_MsoMdoc_Invalid_ThrowsException() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("mso_mdoc");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(MsoMdocCredentialConfigValidator.class)) {
            mocked.when(() -> MsoMdocCredentialConfigValidator.isValidCheckV2(dto)).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true)
            );
            assertEquals("Fields doctype and signatureCryptoSuite are mandatory for the mso_mdoc format.", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_MsoMdoc_Duplicate_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("mso_mdoc");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(MsoMdocCredentialConfigValidator.class)) {
            mocked.when(() -> MsoMdocCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            mocked.when(() -> MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(eq(dto), any())).thenReturn(true);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
            );
            assertEquals("Configuration already exists for the specified doctype.", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfigurationV2_MsoMdoc_Duplicate_ThrowsException() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("mso_mdoc");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(MsoMdocCredentialConfigValidator.class)) {
            mocked.when(() -> MsoMdocCredentialConfigValidator.isValidCheckV2(dto)).thenReturn(true);
            mocked.when(() -> MsoMdocCredentialConfigValidator.isConfigAlreadyPresentV2(eq(dto), any())).thenReturn(true);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true)
            );
            assertEquals("Configuration already exists for the specified doctype.", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_SdJwt_Invalid_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("vc+sd-jwt");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(SdJwtCredentialConfigValidator.class)) {
            mocked.when(() -> SdJwtCredentialConfigValidator.isValidCheck(dto)).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
            );
            assertEquals("Fields vct and signatureAlgo are mandatory for the vc+sd-jwt format.", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfigurationV2_SdJwt_Invalid_ThrowsException() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("vc+sd-jwt");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(SdJwtCredentialConfigValidator.class)) {
            mocked.when(() -> SdJwtCredentialConfigValidator.isValidCheckV2(dto)).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true)
            );
            assertEquals("Fields vct and signatureAlgo are mandatory for the vc+sd-jwt format.", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_SdJwt_Duplicate_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("vc+sd-jwt");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(SdJwtCredentialConfigValidator.class)) {
            mocked.when(() -> SdJwtCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            mocked.when(() -> SdJwtCredentialConfigValidator.isConfigAlreadyPresent(eq(dto), any())).thenReturn(true);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
            );
            assertEquals("Configuration already exists for the specified vct.", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfigurationV2_SdJwt_Duplicate_ThrowsException() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("vc+sd-jwt");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(SdJwtCredentialConfigValidator.class)) {
            mocked.when(() -> SdJwtCredentialConfigValidator.isValidCheckV2(dto)).thenReturn(true);
            mocked.when(() -> SdJwtCredentialConfigValidator.isConfigAlreadyPresentV2(eq(dto), any())).thenReturn(true);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true)
            );
            assertEquals("Configuration already exists for the specified vct.", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_LdpVc_MissingSignatureAlgo_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setSignatureCryptoSuite("test-rdfc-2019");
        dto.setSignatureAlgo("");
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            mocked.when(() -> LdpVcCredentialConfigValidator.isConfigAlreadyPresent(eq(dto), any())).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
            );
            assertEquals("Unsupported signature crypto suite: test-rdfc-2019", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfigurationV2_LdpVc_MissingSignatureAlgo_ThrowsException() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setSignatureCryptoSuite("test-rdfc-2019");
        dto.setSignatureAlgo("");
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheckV2(dto)).thenReturn(true);
            mocked.when(() -> LdpVcCredentialConfigValidator.isConfigAlreadyPresentV2(eq(dto), any())).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true)
            );
            assertEquals("Unsupported signature crypto suite: test-rdfc-2019", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_MultipleCredentialStatusPurposes_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(List.of("purpose1", "purpose2"));
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1"));
        CertifyException ex = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
        );
        assertEquals("Multiple credential status purposes are not supported. Please specify only one.", ex.getMessage());
    }

    @Test
    public void validateCredentialConfigurationV2_MultipleCredentialStatusPurposes_ThrowsException() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(List.of("purpose1", "purpose2"));
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1"));
        CertifyException ex = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true)
        );
        assertEquals("Multiple credential status purposes are not supported. Please specify only one.", ex.getMessage());
    }

    @Test
    public void validateCredentialConfiguration_InvalidCredentialStatusPurpose_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(List.of("invalid_purpose"));
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1", "purpose2"));
        CertifyException ex = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
        );
        assertEquals("Invalid credential status purpose. Allowed values are: [purpose1, purpose2]", ex.getMessage());
    }

    @Test
    public void validateCredentialConfigurationV2_InvalidCredentialStatusPurpose_ThrowsException() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(List.of("invalid_purpose"));
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1", "purpose2"));
        CertifyException ex = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true)
        );
        assertEquals("Invalid credential status purpose. Allowed values are: [purpose1, purpose2]", ex.getMessage());
    }

    @Test
    public void validateCredentialConfiguration_NullCredentialStatusPurposes_AllowsConfig() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(null);
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential"));
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("TEST2019");
        dto.setKeyManagerRefId("TEST2019-REF");
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1", "purpose2"));
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true);
        }
    }

    @Test
    public void validateCredentialConfigurationV2_NullCredentialStatusPurposes_AllowsConfig() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(null);
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential"));
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("TEST2019");
        dto.setKeyManagerRefId("TEST2019-REF");
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1", "purpose2"));
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheckV2(dto)).thenReturn(true);
            ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true);
        }
    }

    @Test
    public void validateCredentialConfiguration_EmptyCredentialStatusPurposes_AllowsConfig() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(Collections.emptyList());
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential"));
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("TEST2019");
        dto.setKeyManagerRefId("TEST2019-REF");
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1", "purpose2"));
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true);
        }
    }

    @Test
    public void validateCredentialConfigurationV2_EmptyCredentialStatusPurposes_AllowsConfig() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(Collections.emptyList());
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential"));
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("TEST2019");
        dto.setKeyManagerRefId("TEST2019-REF");
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1", "purpose2"));
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheckV2(dto)).thenReturn(true);
            ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true);
        }
    }

    @Test
    public void validateCredentialConfiguration_ValidSingleCredentialStatusPurpose_Succeeds() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(List.of("purpose1"));
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential"));
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("TEST2019");
        dto.setKeyManagerRefId("TEST2019-REF");
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1", "purpose2"));
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true);
        }
    }

    @Test
    public void validateCredentialConfigurationV2_ValidSingleCredentialStatusPurpose_Succeeds() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(List.of("purpose1"));
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential"));
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("TEST2019");
        dto.setKeyManagerRefId("TEST2019-REF");
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1", "purpose2"));
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheckV2(dto)).thenReturn(true);
            ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true);
        }
    }

    @Test
    public void validateKeyAliasMapperConfiguration_KeyAliasListIsNull_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc"); // Required to avoid NPE in switch statement
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        dto.setSignatureCryptoSuite("RsaSignature2018");
        dto.setSignatureAlgo("RS256");
        dto.setVcTemplate("test_template");

        // Act & Assert
        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.addCredentialConfiguration(dto)
        );
        assertEquals("No key chooser configuration found for the signature crypto suite: RsaSignature2018", exception.getMessage());
    }

    @Test
    public void validateKeyAliasMapperConfigurationV2_KeyAliasListIsNull_ThrowsException() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc"); // Required to avoid NPE in switch statement
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        dto.setSignatureCryptoSuite("RsaSignature2018");
        dto.setSignatureAlgo("RS256");
        dto.setVcTemplate("test_template");

        // Act & Assert
        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.addCredentialConfigurationV2(dto)
        );
        assertEquals("No key chooser configuration found for the signature crypto suite: RsaSignature2018", exception.getMessage());
    }

    @Test
    public void validateKeyAliasMpperConfiguration_NoMatchingAppIdAndRefId_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc"); // Required to avoid NPE in switch statement
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("appId");
        dto.setKeyManagerRefId("refId");
        dto.setVcTemplate("test_template");

        // Act & Assert
        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.addCredentialConfiguration(dto)
        );
        assertEquals("No matching appId and refId found in the key chooser configuration.", exception.getMessage());
    }

    @Test
    public void validateKeyAliasMpperConfigurationV2_NoMatchingAppIdAndRefId_ThrowsException() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc"); // Required to avoid NPE in switch statement
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("appId");
        dto.setKeyManagerRefId("refId");
        dto.setVcTemplate("test_template");

        // Act & Assert
        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.addCredentialConfigurationV2(dto)
        );
        assertEquals("No matching appId and refId found in the key chooser configuration.", exception.getMessage());
    }

    // Java
    @Test
    public void validateCredentialConfiguration_QrSettingsNull_QrSignatureAlgoSet_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setQrSettings(null);
        dto.setQrSignatureAlgo("EdDSA");
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        CertifyException ex = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
        );
        assertEquals("QR signature algorithm is not allowed when QR settings are not set.", ex.getMessage());
    }

    @Test
    public void validateCredentialConfigurationV2_QrSettingsNull_QrSignatureAlgoSet_ThrowsException() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setQrSettings(null);
        dto.setQrSignatureAlgo("EdDSA");
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        CertifyException ex = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true)
        );
        assertEquals("QR signature algorithm is not allowed when QR settings are not set.", ex.getMessage());
    }

    @Test
    public void validateCredentialConfiguration_QrSettingsEmpty_QrSignatureAlgoSet_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setQrSettings(Collections.emptyList());
        dto.setQrSignatureAlgo("EdDSA");
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        CertifyException ex = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
        );
        assertEquals("QR signature algorithm is not allowed when QR settings are not set.", ex.getMessage());
    }

    @Test
    public void validateCredentialConfigurationV2_QrSettingsEmpty_QrSignatureAlgoSet_ThrowsException() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setQrSettings(Collections.emptyList());
        dto.setQrSignatureAlgo("EdDSA");
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        CertifyException ex = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true)
        );
        assertEquals("QR signature algorithm is not allowed when QR settings are not set.", ex.getMessage());
    }

    @Test
    public void validateCredentialConfiguration_QrSettingsPresent_UnsupportedQrSignatureAlgo_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setQrSettings(List.of(Map.of("key", "value")));
        dto.setQrSignatureAlgo("UNSUPPORTED_ALGO");
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper", Map.of("EdDSA", List.of(List.of("TEST2019", "TEST2019-REF"))));
        CertifyException ex = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
        );
        assertEquals("The algorithm UNSUPPORTED_ALGO is not supported for QR signing. The supported values are: [EdDSA]", ex.getMessage());
    }

    @Test
    public void validateCredentialConfigurationV2_QrSettingsPresent_UnsupportedQrSignatureAlgo_ThrowsException() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setQrSettings(List.of(Map.of("key", "value")));
        dto.setQrSignatureAlgo("UNSUPPORTED_ALGO");
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper", Map.of("EdDSA", List.of(List.of("TEST2019", "TEST2019-REF"))));
        CertifyException ex = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true)
        );
        assertEquals("The algorithm UNSUPPORTED_ALGO is not supported for QR signing. The supported values are: [EdDSA]", ex.getMessage());
    }

    @Test
    public void validateCredentialConfiguration_QrSettingsPresent_SupportedQrSignatureAlgo_AllowsConfig() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setQrSettings(List.of(Map.of("key", "value")));
        dto.setSignatureAlgo("EdDSA");
        dto.setQrSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("TEST2019");
        dto.setKeyManagerRefId("TEST2019-REF");
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper", Map.of("EdDSA", List.of(List.of("TEST2019", "TEST2019-REF"))));
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true);
        }
    }

    @Test
    public void validateCredentialConfigurationV2_QrSettingsPresent_SupportedQrSignatureAlgo_AllowsConfig() {
        CredentialConfigurationDTOV2 dto = new CredentialConfigurationDTOV2();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setQrSettings(List.of(Map.of("key", "value")));
        dto.setSignatureAlgo("EdDSA");
        dto.setQrSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("TEST2019");
        dto.setKeyManagerRefId("TEST2019-REF");
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper", Map.of("EdDSA", List.of(List.of("TEST2019", "TEST2019-REF"))));
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheckV2(dto)).thenReturn(true);
            ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfigurationV2", dto, true);
        }
    }

    @Test
    public void resolveAuthorizationServers_MultipleServers_Success() {
        // Setup multiple servers in authUrl
        ReflectionTestUtils.setField(credentialConfigurationService, "authUrl", "http://auth1.com, http://auth2.com ");

        // Setup mappings
        Map<String, String> authServerMapping = new HashMap<>();
        authServerMapping.put("Farmer", "http://farmer-as.com");
        authServerMapping.put("Default", "http://auth1.com"); // Duplicate
        ReflectionTestUtils.setField(credentialConfigurationService, "authorizationServerMapping", authServerMapping);

        when(credentialConfigRepository.findAll()).thenReturn(Collections.emptyList());

        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        List<String> servers = result.getAuthorizationServers();
        Assert.assertNotNull(servers);
        Assert.assertEquals(3, servers.size());
        Assert.assertTrue(servers.contains("http://auth1.com"));
        Assert.assertTrue(servers.contains("http://auth2.com"));
        Assert.assertTrue(servers.contains("http://farmer-as.com"));
        // Order should be preserved if LinkedHashSet is used
        Assert.assertEquals("http://auth1.com", servers.get(0));
        Assert.assertEquals("http://auth2.com", servers.get(1));
        Assert.assertEquals("http://farmer-as.com", servers.get(2));
    }

    @Test
    public void resolveAuthorizationServers_AuthUrlIsNull_ReturnsOnlyMappingServers() {
        // authUrl is null
        ReflectionTestUtils.setField(credentialConfigurationService, "authUrl", null);

        Map<String, String> authServerMapping = new HashMap<>();
        authServerMapping.put("default", "http://mapping-server.com");
        ReflectionTestUtils.setField(credentialConfigurationService, "authorizationServerMapping", authServerMapping);

        when(credentialConfigRepository.findAll()).thenReturn(Collections.emptyList());

        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        List<String> servers = result.getAuthorizationServers();
        Assert.assertNotNull(servers);
        Assert.assertEquals(1, servers.size());
        Assert.assertTrue(servers.contains("http://mapping-server.com"));
    }

    @Test
    public void resolveAuthorizationServers_SingleAuthUrl_NoSplitRequired_ReturnsAllServers() {
        // authUrl has only 1 value — comma-split won't produce multiple entries
        ReflectionTestUtils.setField(credentialConfigurationService, "authUrl", "http://single-auth.com");

        Map<String, String> authServerMapping = new HashMap<>();
        authServerMapping.put("extra", "http://extra-server.com");
        ReflectionTestUtils.setField(credentialConfigurationService, "authorizationServerMapping", authServerMapping);

        when(credentialConfigRepository.findAll()).thenReturn(Collections.emptyList());

        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        List<String> servers = result.getAuthorizationServers();
        Assert.assertNotNull(servers);
        Assert.assertEquals(2, servers.size());
        Assert.assertTrue(servers.contains("http://single-auth.com"));
        Assert.assertTrue(servers.contains("http://extra-server.com"));
        Assert.assertEquals("http://single-auth.com", servers.get(0));
        Assert.assertEquals("http://extra-server.com", servers.get(1));
    }

    @Test
    public void resolveAuthorizationServers_MappingIsNull_ReturnsOnlyAuthUrlServers() {
        // authorizationServerMapping is null
        ReflectionTestUtils.setField(credentialConfigurationService, "authUrl", "http://auth1.com, http://auth2.com");
        ReflectionTestUtils.setField(credentialConfigurationService, "authorizationServerMapping", null);

        when(credentialConfigRepository.findAll()).thenReturn(Collections.emptyList());

        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        List<String> servers = result.getAuthorizationServers();
        Assert.assertNotNull(servers);
        Assert.assertEquals(2, servers.size());
        Assert.assertEquals("http://auth1.com", servers.get(0));
        Assert.assertEquals("http://auth2.com", servers.get(1));
    }

    @Test
    public void resolveAuthorizationServers_MappingIsEmpty_ReturnsOnlyAuthUrlServers() {
        // authorizationServerMapping is an empty map
        ReflectionTestUtils.setField(credentialConfigurationService, "authUrl", "http://auth1.com, http://auth2.com");
        ReflectionTestUtils.setField(credentialConfigurationService, "authorizationServerMapping", new HashMap<>());

        when(credentialConfigRepository.findAll()).thenReturn(Collections.emptyList());

        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        List<String> servers = result.getAuthorizationServers();
        Assert.assertNotNull(servers);
        Assert.assertEquals(2, servers.size());
        Assert.assertEquals("http://auth1.com", servers.get(0));
        Assert.assertEquals("http://auth2.com", servers.get(1));
    }

}
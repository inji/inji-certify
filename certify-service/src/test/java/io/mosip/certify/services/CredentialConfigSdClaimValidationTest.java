package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.CredentialConfigMapper;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class CredentialConfigSdClaimValidationTest {

    /** Replace with ErrorConstants.INVALID_SD_CLAIM once the constant is introduced. */
    private static final String INVALID_SD_CLAIM = "invalid_sd_claim";

    @Mock
    private CredentialConfigRepository credentialConfigRepository;

    @Mock
    private CredentialConfigMapper credentialConfigMapper;

    @InjectMocks
    private CredentialConfigurationServiceImpl credentialConfigurationService;

    @Before
    public void setup() {
        LinkedHashMap<String, List<String>> bindingMethods = new LinkedHashMap<>();
        bindingMethods.put("ldp_vc", List.of("did:jwk", "did:web"));
        bindingMethods.put("mso_mdoc", List.of("cose_key"));
        bindingMethods.put("dc+sd-jwt", List.of("did:jwk", "did:web"));

        LinkedHashMap<String, List<String>> signingAlgs = new LinkedHashMap<>();
        signingAlgs.put("Ed25519Signature2020", List.of("EdDSA"));
        signingAlgs.put("EcdsaSecp256r1Signature2019", List.of("ES256"));

        LinkedHashMap<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", Map.of(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED,
                List.of("RS256", "PS256", "ES256", "EdDSA")));

        Map<String, List<List<String>>> keyAliasMapper = new HashMap<>();
        keyAliasMapper.put("EdDSA", List.of(List.of("TEST2019", "TEST2019-REF")));
        keyAliasMapper.put("ES256", List.of(List.of("TEST_EC", "TEST_EC-REF")));

        ReflectionTestUtils.setField(credentialConfigurationService, "credentialIssuer", "http://example.com/");
        ReflectionTestUtils.setField(credentialConfigurationService, "authUrl", "http://auth.com");
        ReflectionTestUtils.setField(credentialConfigurationService, "servletPath", "v1/test");
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        ReflectionTestUtils.setField(credentialConfigurationService, "issuerDisplay", List.of(Map.of()));
        ReflectionTestUtils.setField(credentialConfigurationService, "cryptographicBindingMethodsSupportedMap", bindingMethods);
        ReflectionTestUtils.setField(credentialConfigurationService, "credentialSigningAlgValuesSupportedMap", signingAlgs);
        ReflectionTestUtils.setField(credentialConfigurationService, "proofTypesSupported", proofTypes);
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper", keyAliasMapper);
        ReflectionTestUtils.setField(credentialConfigurationService, "authorizationServerMapping", Map.of());
    }

    // ------------------------------------------------------------------ fixtures

    private CredentialConfigurationDTO sdJwtRequest(String sdClaim) {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId("test-sd-jwt");
        dto.setMetaDataDisplay(List.of(new MetaDataDisplayDTO()));
        dto.setVcTemplate("test_template");
        dto.setCredentialFormat("dc+sd-jwt");
        dto.setSdJwtVct("test-vct");
        dto.setSignatureAlgo("ES256");
        dto.setSdClaim(sdClaim);
        return dto;
    }

    private CredentialConfigurationDTO ldpVcRequest(String sdClaim) {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId("test-credential");
        dto.setMetaDataDisplay(List.of(new MetaDataDisplayDTO()));
        dto.setVcTemplate("test_template");
        dto.setCredentialFormat("ldp_vc");
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("TEST2019");
        dto.setKeyManagerRefId("TEST2019-REF");
        dto.setSdClaim(sdClaim);
        return dto;
    }

    private CredentialConfigurationDTO msoMdocRequest(String sdClaim) {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId("test-mso-mdoc");
        dto.setMetaDataDisplay(List.of(new MetaDataDisplayDTO()));
        dto.setVcTemplate("test_template");
        dto.setCredentialFormat("mso_mdoc");
        dto.setDocType("org.iso.18013.5.1.mDL");
        dto.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        dto.setSdClaim(sdClaim);
        return dto;
    }

    /** An entity shaped like the request, so metadata resolution behaves as it would in production. */
    private CredentialConfig entityFor(CredentialConfigurationDTO request) {
        CredentialConfig entity = new CredentialConfig();
        entity.setCredentialConfigKeyId(request.getCredentialConfigKeyId());
        entity.setStatus("active");
        entity.setCredentialFormat(request.getCredentialFormat());
        entity.setSdJwtVct(request.getSdJwtVct());
        entity.setDocType(request.getDocType());
        entity.setSignatureAlgo(request.getSignatureAlgo());
        entity.setSignatureCryptoSuite(request.getSignatureCryptoSuite());
        return entity;
    }

    // ------------------------------------------------------------------ assertions

    /**
     * Adding this configuration must be refused because of its sdClaim, with nothing persisted.
     *
     * @param offendingEntry the entry the message has to name, or null to skip that check when the
     *                       offender is a blank and there is no text to look for
     */
    private void assertAddRejected(CredentialConfigurationDTO request, String offendingEntry) {
        CredentialConfig entity = entityFor(request);
        lenient().when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        lenient().when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        try {
            credentialConfigurationService.addCredentialConfiguration(request);
            Assert.fail("sdClaim <" + request.getSdClaim() + "> must be rejected on add, "
                    + "but the configuration was accepted");
        } catch (CertifyException e) {
            Assert.assertEquals("wrong errorCode for sdClaim <" + request.getSdClaim() + ">",
                    INVALID_SD_CLAIM, e.getErrorCode());
            if (offendingEntry != null) {
                Assert.assertTrue("error message should name the offending entry <" + offendingEntry
                        + "> but was: " + e.getMessage(), e.getMessage().contains(offendingEntry));
            }
        }
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    private void assertAddAccepted(CredentialConfigurationDTO request) {
        CredentialConfig entity = entityFor(request);
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(request);

        verify(credentialConfigRepository).save(any(CredentialConfig.class));
    }

    /**
     * Updating must be refused because of the sdClaim the merged configuration carries.
     * <p>
     * The service validates the stored entity merged with the request, which it reads back through
     * the mapper, so the merged view is what has to carry the sdClaim under test.
     */
    private void assertUpdateRejected(String sdClaim, String offendingEntry) {
        CredentialConfig stored = entityFor(sdJwtRequest("$.fullName"));
        CredentialConfigurationDTO request = sdJwtRequest(sdClaim);

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-sd-jwt"))
                .thenReturn(Optional.of(stored));
        doNothing().when(credentialConfigMapper)
                .updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(sdJwtRequest(sdClaim));
        lenient().when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(stored);

        try {
            credentialConfigurationService.updateCredentialConfiguration("test-sd-jwt", request);
            Assert.fail("sdClaim <" + sdClaim + "> must be rejected on update, "
                    + "but the configuration was accepted");
        } catch (CertifyException e) {
            Assert.assertEquals("wrong errorCode for sdClaim <" + sdClaim + ">",
                    INVALID_SD_CLAIM, e.getErrorCode());
            if (offendingEntry != null) {
                Assert.assertTrue("error message should name the offending entry <" + offendingEntry
                        + "> but was: " + e.getMessage(), e.getMessage().contains(offendingEntry));
            }
        }
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    // ---------- N1: an entry that is not rooted at $ is not a selective disclosure path ----------

    /**
     * The ticket's own reproduction step: sd_claims set to random values. Today the configuration is
     * added successfully.
     */
    @Test
    public void addWithSdClaimRandomValue_IsRejected() {
        assertAddRejected(sdJwtRequest("abcdef"), "abcdef");
    }

    @Test
    public void addWithSdClaimMissingRoot_IsRejected() {
        assertAddRejected(sdJwtRequest("fullName"), "fullName");
    }

    @Test
    public void addWithSdClaimLeadingDotWithoutRoot_IsRejected() {
        assertAddRejected(sdJwtRequest(".fullName"), ".fullName");
    }

    // ---------- N2: an entry outside the supported JSONPath subset ----------

    @Test
    public void addWithSdClaimRecursiveDescent_IsRejected() {
        assertAddRejected(sdJwtRequest("$..fullName"), "$..fullName");
    }

    @Test
    public void addWithSdClaimZeroPaddedArrayIndex_IsRejected() {
        assertAddRejected(sdJwtRequest("$.phoneNumbers[01]"), "$.phoneNumbers[01]");
    }

    @Test
    public void addWithSdClaimNonNumericArrayIndex_IsRejected() {
        assertAddRejected(sdJwtRequest("$.phoneNumbers[x]"), "$.phoneNumbers[x]");
    }

    @Test
    public void addWithSdClaimTrailingDot_IsRejected() {
        assertAddRejected(sdJwtRequest("$.address."), "$.address.");
    }

    @Test
    public void addWithSdClaimBlankEntryBetweenSeparators_IsRejected() {
        assertAddRejected(sdJwtRequest("$.fullName,,$.gender"), null);
    }

    @Test
    public void addWithSdClaimWhitespaceOnlyEntry_IsRejected() {
        assertAddRejected(sdJwtRequest("$.fullName, ,$.gender"), null);
    }

    /**
     * Load bearing. String.split(",") discards trailing empty strings, so "," and ",," both split to
     * a ZERO length array and {@code Arrays.stream(sdClaim.split(",")).allMatch(...)} is vacuously
     * true for them. An implementation written that way accepts both; this test is what rejects it.
     */
    @Test
    public void addWithSdClaimSeparatorsOnly_IsRejected() {
        assertAddRejected(sdJwtRequest(","), null);
    }

    /** A value made only of whitespace is a blank entry once trimmed. */
    @Test
    public void addWithSdClaimWhitespaceOnlyValue_IsRejected() {
        assertAddRejected(sdJwtRequest("   "), null);
    }

    /**
     * Trailing blanks are rejected rather than tolerated. Because split(",") drops them,
     * "$.fullName," reads as one valid entry unless validation splits with a negative limit, which
     * keeps every position. Issuance would in fact cope with this value, so the rule here is
     * deliberately stricter than the runtime: every position between separators must be a path, with
     * no exception to explain.
     */
    @Test
    public void addWithSdClaimTrailingSeparator_IsRejected() {
        assertAddRejected(sdJwtRequest("$.fullName,"), null);
    }

    @Test
    public void addWithSdClaimTrailingSeparators_IsRejected() {
        assertAddRejected(sdJwtRequest("$.fullName,,"), null);
    }

    /**
     * An entirely empty sdClaim is rejected rather than read as "no selective disclosure". It is
     * already unusable: getSelectiveDisclosureInfo splits "" into [""], so issuance fails on it with
     * sd_claims_parse_error. Accepting it here would publish a configuration that can never issue.
     */
    @Test
    public void addWithSdClaimEmptyString_IsRejected() {
        assertAddRejected(sdJwtRequest(""), null);
    }

    // ---------- N4: every entry is checked, and a valid entry does not excuse a broken one ----------

    @Test
    public void addWithSdClaimOneValidOneInvalidEntry_IsRejected() {
        assertAddRejected(sdJwtRequest("$.fullName,abcdef"), "abcdef");
    }

    @Test
    public void addWithSdClaimInvalidEntryLast_IsRejected() {
        assertAddRejected(sdJwtRequest("$.fullName, $.gender, $.address[x]"), "$.address[x]");
    }

    // ---------- the check is not specific to dc+sd-jwt ----------

    @Test
    public void addLdpVcWithInvalidSdClaim_IsRejected() {
        assertAddRejected(ldpVcRequest("abcdef"), "abcdef");
    }

    @Test
    public void addMsoMdocWithInvalidSdClaim_IsRejected() {
        assertAddRejected(msoMdocRequest("abcdef"), "abcdef");
    }

    // ---------- R1-R5: well formed values must keep working ----------

    @Test
    public void addWithSdClaimSinglePath_IsAccepted() {
        assertAddAccepted(sdJwtRequest("$.fullName"));
    }

    @Test
    public void addWithSdClaimSeveralPaths_IsAccepted() {
        assertAddAccepted(sdJwtRequest("$.fullName,$.gender"));
    }

    /**
     * getSelectiveDisclosureInfo splits on "," without trimming, and isPathSyntaxValid trims before
     * matching, so a space after a separator is valid today and has to stay valid.
     */
    @Test
    public void addWithSdClaimWhitespaceAfterSeparator_IsAccepted() {
        assertAddAccepted(sdJwtRequest("$.fullName, $.gender"));
    }

    @Test
    public void addWithSdClaimNestedIndexedAndWildcardPaths_IsAccepted() {
        assertAddAccepted(sdJwtRequest(
                "$.address.region, $.phoneNumbers[0], $.phoneNumbers[*], $.address.*"));
    }

    @Test
    public void addWithSdClaimOmitted_IsAccepted() {
        assertAddAccepted(sdJwtRequest(null));
    }

    /**
     * The root on its own is syntactically valid, so it is accepted. Whether disclosing a whole
     * credential is meaningful is a question about the credential rather than about the string, and
     * is therefore not settled at configuration time.
     */
    @Test
    public void addWithSdClaimRootOnly_IsAccepted() {
        assertAddAccepted(sdJwtRequest("$"));
    }

    /**
     * A repeated path is not invalid: the claim is simply disclosed once. Unlike qrSettings, where
     * INJICERT #679 made duplicate fields an error, nothing here requires them to be rejected.
     */
    @Test
    public void addWithSdClaimDuplicatePaths_IsAccepted() {
        assertAddAccepted(sdJwtRequest("$.fullName,$.fullName"));
    }

    // ---------- R6, R7: the scope boundary. Needs credential data, so it stays at VC fetch ----------

    /**
     * Well formed, but no such field in the template. Deciding that needs a rendered credential, and
     * an empty credential cannot be produced from the template, so this is a VC fetch error and has
     * to be accepted here.
     */
    @Test
    public void addWithSdClaimPathNotInTemplate_IsAccepted() {
        assertAddAccepted(sdJwtRequest("$.favouriteColour"));
    }

    /**
     * Well formed, but an array wildcard over what the template emits as a string. Detecting the
     * mismatch needs the rendered value, so it also stays at VC fetch.
     */
    @Test
    public void addWithSdClaimPathOfWrongShape_IsAccepted() {
        assertAddAccepted(sdJwtRequest("$.fullName[*]"));
    }

    // ---------- N5: the update API, which the ticket names alongside add ----------

    @Test
    public void updateWithSdClaimRandomValue_IsRejected() {
        assertUpdateRejected("abcdef", "abcdef");
    }

    @Test
    public void updateWithSdClaimBlankEntry_IsRejected() {
        assertUpdateRejected("$.fullName,,$.gender", null);
    }

    @Test
    public void updateWithSdClaimInvalidAmongValidEntries_IsRejected() {
        assertUpdateRejected("$.fullName, abcdef", "abcdef");
    }

    @Test
    public void updateWithValidSdClaim_IsAccepted() {
        CredentialConfig stored = entityFor(sdJwtRequest("$.fullName"));
        when(credentialConfigRepository.findByCredentialConfigKeyId("test-sd-jwt"))
                .thenReturn(Optional.of(stored));
        doNothing().when(credentialConfigMapper)
                .updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class)))
                .thenReturn(sdJwtRequest("$.fullName, $.address.region"));
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(stored);

        credentialConfigurationService.updateCredentialConfiguration(
                "test-sd-jwt", sdJwtRequest("$.fullName, $.address.region"));

        verify(credentialConfigRepository).save(any(CredentialConfig.class));
    }

    // ---------- ordering: sdClaim is cross-cutting, so it is checked before the format branch ----------

    /**
     * sdClaim is not specific to one format, so its check belongs with the other cross-cutting
     * validations, which run ahead of the format-specific branch. A request that is wrong in both
     * ways reports the sdClaim; this pins that ordering as a deliberate choice rather than an
     * accident of where the call was placed.
     */
    @Test
    public void addWithInvalidSdClaimAndMissingVct_ReportsTheSdClaim() {
        CredentialConfigurationDTO request = sdJwtRequest("abcdef");
        request.setSdJwtVct(null);

        assertAddRejected(request, "abcdef");
    }
}

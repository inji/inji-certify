package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.MdlDataElements;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MsoMdocCredentialConfigValidatorTest {

    @Test
    void testIsValidCheck_validConfig_returnsTrue() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        config.setCredentialTypes(null);
        config.setContextURLs(null);
        config.setSdJwtVct(null);
        config.setClaims(null);
        assertTrue(MsoMdocCredentialConfigValidator.isValidCheck(config, "DataProvider"));
    }

    @Test
    void testIsValidCheck_sdJwtClaimsPresent_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        config.setCredentialTypes(null);
        config.setContextURLs(null);
        config.setSdJwtVct(null);
        config.setClaims(null);
        config.setSdJwtClaims(new HashMap<>());
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config, "DataProvider"));
    }

    @Test
    void testIsValidCheck_missingDocType_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType(null);
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config, "DataProvider"));
    }

    @Test
    void testIsValidCheck_emptyDocType_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config, "DataProvider"));
    }

    @Test
    void should_returnFalse_when_signatureAlgoIsMissingInDataProviderMode() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo(null);
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config, "DataProvider"));
    }

    @Test
    void should_returnFalse_when_signatureAlgoIsEmptyInDataProviderMode() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config, "DataProvider"));
    }

    /**
     * In VCIssuance mode the plugin signs the credential, so signatureAlgo is optional.
     */
    @Test
    void should_returnTrue_when_signatureAlgoIsMissingInVcIssuanceMode() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo(null);
        assertTrue(MsoMdocCredentialConfigValidator.isValidCheck(config, "VCIssuance"));
    }

    /**
     * An mdoc is signed with signatureAlgo alone, so signatureCryptoSuite is optional.
     */
    @Test
    void should_returnTrue_when_signatureCryptoSuiteIsMissing() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        assertTrue(MsoMdocCredentialConfigValidator.isValidCheck(config, "DataProvider"));
    }

    @Test
    void should_returnTrue_when_signatureCryptoSuiteIsEmpty() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("");
        assertTrue(MsoMdocCredentialConfigValidator.isValidCheck(config, "DataProvider"));
    }

    /**
     * The value itself is not validated: any crypto suite name is accepted for mso_mdoc.
     */
    @Test
    void should_returnTrue_when_signatureCryptoSuiteIsAnyValue() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("NotADeclaredSuite");
        assertTrue(MsoMdocCredentialConfigValidator.isValidCheck(config, "DataProvider"));
    }

    @Test
    void testIsValidCheck_credentialTypeNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        config.setCredentialTypes(List.of("type"));
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config, "DataProvider"));
    }

    @Test
    void testIsValidCheck_contextNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        config.setContextURLs(List.of("someContext URL"));
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config, "DataProvider"));
    }

    @Test
    void testIsValidCheck_sdJwtVctNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        config.setSdJwtVct("sdJwtVct");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config, "DataProvider"));
    }

    @Test
    void testIsValidCheck_credentialSubjectNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        config.setClaims(new HashMap<>());
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config, "DataProvider"));
    }

    @Test
    void testIsConfigAlreadyPresent_present_returnsTrue() {
        CredentialConfigurationDTO config = Mockito.mock(CredentialConfigurationDTO.class);
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(config.getCredentialFormat()).thenReturn("format");
        Mockito.when(config.getDocType()).thenReturn("docType");
        Mockito.when(repo.findByCredentialFormatAndDocType("format", "docType"))
                .thenReturn(Optional.of(new io.mosip.certify.entity.CredentialConfig()));
        assertTrue(MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(config, repo));
    }

    @Test
    void testIsConfigAlreadyPresent_notPresent_returnsFalse() {
        CredentialConfigurationDTO config = Mockito.mock(CredentialConfigurationDTO.class);
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(config.getCredentialFormat()).thenReturn("format");
        Mockito.when(config.getDocType()).thenReturn("docType");
        Mockito.when(repo.findByCredentialFormatAndDocType("format", "docType"))
                .thenReturn(Optional.empty());
        assertFalse(MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(config, repo));
    }

    // ---------- ISO/IEC 18013-5 Table 5 mandatory elements ----------

    @Test
    void should_reportMissingElements_when_mdlTemplateLacksMandatoryOnes() {
        CredentialConfigurationDTO config = mdlConfig(mdlTemplate(MdlDataElements.NAMESPACE,
                List.of("family_name", "given_name", "birth_date", "document_number")));

        assertEquals(List.of("issue_date", "expiry_date", "issuing_country", "issuing_authority", "portrait",
                        "driving_privileges", "un_distinguishing_sign"),
                MsoMdocCredentialConfigValidator.findMissingMdlElements(config, "DataProvider"));
    }

    @Test
    void should_reportNothing_when_mdlTemplateHasEveryMandatoryElement() {
        CredentialConfigurationDTO config = mdlConfig(mdlTemplate(MdlDataElements.NAMESPACE, MdlDataElements.MANDATORY));

        assertTrue(MsoMdocCredentialConfigValidator.findMissingMdlElements(config, "DataProvider").isEmpty());
    }

    @Test
    void should_countOnlyTheMdlNamespace_when_anElementIsDeclaredElsewhere() {
        // family_name in another namespace is not the mDL's family_name
        CredentialConfigurationDTO config = mdlConfig(mdlTemplate("org.example.custom", MdlDataElements.MANDATORY));

        assertEquals(MdlDataElements.MANDATORY,
                MsoMdocCredentialConfigValidator.findMissingMdlElements(config, "DataProvider"));
    }

    @Test
    void should_notCheckTheTemplate_when_templateUsesVelocityDirectives() {
        // #foreach makes the template invalid JSON until Velocity renders it, so which namespace
        // each identifier lands in is unknown: the mandatory ones here are in a custom namespace.
        String elements = MdlDataElements.MANDATORY.stream()
                .map(element -> "{\"elementIdentifier\": \"" + element + "\", \"elementValue\": \"x\"}")
                .collect(Collectors.joining(", "));
        String template = "{\"nameSpaces\": {\"" + MdlDataElements.NAMESPACE + "\": [{\"elementIdentifier\": \"family_name\"}"
                + "#foreach($extra in $extras), {\"elementIdentifier\": \"$extra\"}#end],"
                + " \"org.example.custom\": [" + elements + "]}}";
        CredentialConfigurationDTO config = mdlConfig(Base64.getEncoder().encodeToString(template.getBytes(StandardCharsets.UTF_8)));

        assertTrue(MsoMdocCredentialConfigValidator.findMissingMdlElements(config, "DataProvider").isEmpty());
    }

    @Test
    void should_notCheckTheTemplate_when_anMdlIdentifierIsAVelocityReference() {
        // the identifier is only known once rendered, e.g. from elements the DataProvider returns
        List<String> elements = List.of("family_name", "${element.identifier}");
        CredentialConfigurationDTO config = mdlConfig(mdlTemplate(MdlDataElements.NAMESPACE, elements));

        assertTrue(MsoMdocCredentialConfigValidator.findMissingMdlElements(config, "DataProvider").isEmpty());
    }

    @Test
    void should_notCheckTheTemplate_when_theNamespaceIsAVelocityReference() {
        // ${namespace} may render as org.iso.18013.5.1, so the mDL namespace can't be found before rendering
        CredentialConfigurationDTO config = mdlConfig(mdlTemplate("${namespace}", MdlDataElements.MANDATORY));

        assertTrue(MsoMdocCredentialConfigValidator.findMissingMdlElements(config, "DataProvider").isEmpty());
    }

    @Test
    void should_notCheckTheTemplate_when_docTypeIsNotAnMdl() {
        CredentialConfigurationDTO config = mdlConfig(mdlTemplate(MdlDataElements.NAMESPACE, List.of("family_name")));
        config.setDocType("org.example.custom.document");

        assertTrue(MsoMdocCredentialConfigValidator.findMissingMdlElements(config, "DataProvider").isEmpty());
    }

    @Test
    void should_notCheckTheTemplate_when_pluginModeIsVcIssuance() {
        // the VCIssuance plugin builds the mDL, not this template
        CredentialConfigurationDTO config = mdlConfig(mdlTemplate(MdlDataElements.NAMESPACE, List.of("family_name")));

        assertTrue(MsoMdocCredentialConfigValidator.findMissingMdlElements(config, "VCIssuance").isEmpty());
    }

    @Test
    void should_reportEveryElement_when_mdlTemplateIsMissing() {
        assertEquals(MdlDataElements.MANDATORY,
                MsoMdocCredentialConfigValidator.findMissingMdlElements(mdlConfig(null), "DataProvider"));
    }

    private static CredentialConfigurationDTO mdlConfig(String vcTemplate) {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType(MdlDataElements.DOC_TYPE);
        config.setSignatureAlgo("ES256");
        config.setVcTemplate(vcTemplate);
        return config;
    }

    /** A base64 template declaring the given elements in one namespace. */
    private static String mdlTemplate(String namespace, List<String> elements) {
        String items = elements.stream()
                .map(element -> "{\"elementIdentifier\": \"" + element + "\", \"elementValue\": \"x\"}")
                .collect(Collectors.joining(", "));
        String template = "{\"docType\": \"${_doctype}\", \"nameSpaces\": {\"" + namespace + "\": [" + items + "]}}";
        return Base64.getEncoder().encodeToString(template.getBytes(StandardCharsets.UTF_8));
    }
}
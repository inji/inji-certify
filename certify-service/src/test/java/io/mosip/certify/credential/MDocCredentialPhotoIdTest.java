package io.mosip.certify.credential;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.config.MDocConfig;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.utils.MDocProcessor;
import io.mosip.certify.utils.PhotoIdDataElements;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.signature.dto.CoseSignRequestDto;
import io.mosip.kernel.signature.dto.CoseSignResponseDto;
import io.mosip.kernel.signature.service.CoseSignatureService;
import io.mosip.kernel.signature.service.SignatureService;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.BigIntegers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Issues an ISO/IEC TS 23220 Photo ID (org.iso.23220.photoid.1) through MDocCredential with the real
 * MDocProcessor, and decodes the result independently. Only the outside services are stubbed: the template
 * formatter returns a rendered Photo ID template, and the keymanager COSE call signs with a test P-256 key
 * whose certificate it puts in x5chain, as keymanager does.
 */
@RunWith(MockitoJUnitRunner.class)
public class MDocCredentialPhotoIdTest {

    private static final String TEMPLATE_NAME = "PhotoIDCredential";
    private static final String APP_ID = "CERTIFY_VC_SIGN_EC_R1";
    private static final String REF_ID = "EC_SECP256R1_SIGN";
    private static final String PHOTO_ID_PROFILE_NAMESPACE = "org.iso.23220.photoid.1";
    private static final byte[] JPEG = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, 0x00, 0x10, 0x4A, 0x46};

    @Mock
    private VCFormatter vcFormatter;

    @Mock
    private CoseSignatureService coseSignatureService;

    @Mock
    private KeymanagerService keymanagerService;

    private MDocCredential mDocCredential;
    private KeyPair issuerKey;
    private byte[] issuerCertificate;
    private ECPublicKey holderKey;

    @Before
    public void setUp() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        MDocProcessor processor = new MDocProcessor(objectMapper, new MDocConfig(), coseSignatureService, keymanagerService);
        mDocCredential = new MDocCredential(vcFormatter, mock(SignatureService.class), coseSignatureService, objectMapper, processor);

        issuerKey = p256KeyPair();
        issuerCertificate = certificate(issuerKey);
        holderKey = (ECPublicKey) p256KeyPair().getPublic();

        KeyPairGenerateResponseDto certificate = new KeyPairGenerateResponseDto();
        certificate.setCertificate("-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(issuerCertificate)
                + "\n-----END CERTIFICATE-----\n");
        when(keymanagerService.getCertificate(APP_ID, Optional.of(REF_ID))).thenReturn(certificate);
        when(vcFormatter.getAppID(TEMPLATE_NAME)).thenReturn(APP_ID);
        when(vcFormatter.getRefID(TEMPLATE_NAME)).thenReturn(REF_ID);
        lenient().when(coseSignatureService.coseSign1(any())).thenAnswer(call -> coseSign1(call.getArgument(0)));
    }

    @Test
    public void should_issueAPhotoIdThatDecodesAsTheSpecificationRequires_when_photoIdTemplateIsRendered() throws Exception {
        Map<String, Object> templateParams = holderParams();
        when(vcFormatter.format(templateParams)).thenReturn(renderedPhotoIdTemplate("Doe", true));

        String vcToSign = mDocCredential.createCredential(templateParams, TEMPLATE_NAME);
        VCResult<?> result = mDocCredential.addProof(vcToSign, null, "ES256", APP_ID, REF_ID, "did:example:issuer", null);

        DataItem issuerSigned = decode(Base64.getUrlDecoder().decode((String) result.getCredential()));

        // issuerAuth: an ES256 COSE_Sign1 whose x5chain is the signing certificate and whose signature verifies
        Array issuerAuth = (Array) get(issuerSigned, "issuerAuth");
        byte[] protectedHeader = ((ByteString) issuerAuth.getDataItems().get(0)).getBytes();
        assertEquals(new NegativeInteger(-7), ((co.nstant.in.cbor.model.Map) decode(protectedHeader)).get(new UnsignedInteger(1)));
        assertArrayEquals(issuerCertificate,
                ((ByteString) ((co.nstant.in.cbor.model.Map) issuerAuth.getDataItems().get(1)).get(new UnsignedInteger(33))).getBytes());
        byte[] payload = ((ByteString) issuerAuth.getDataItems().get(2)).getBytes();
        byte[] signature = ((ByteString) issuerAuth.getDataItems().get(3)).getBytes();
        assertTrue("issuerAuth signature", verifies(certificatePublicKey(), protectedHeader, payload, signature));

        // MSO: the Photo ID docType, and a device key that is the holder's proof key
        DataItem mso = decode(((ByteString) decode(payload)).getBytes());
        assertEquals(new UnicodeString(PhotoIdDataElements.DOC_TYPE), get(mso, "docType"));
        assertEquals(new UnicodeString("SHA-256"), get(mso, "digestAlgorithm"));
        co.nstant.in.cbor.model.Map deviceKey = (co.nstant.in.cbor.model.Map) get(get(mso, "deviceKeyInfo"), "deviceKey");
        assertArrayEquals(coordinate(holderKey.getW().getAffineX()), ((ByteString) deviceKey.get(new NegativeInteger(-2))).getBytes());
        assertArrayEquals(coordinate(holderKey.getW().getAffineY()), ((ByteString) deviceKey.get(new NegativeInteger(-3))).getBytes());

        // every element matches its digest in the MSO, in both namespaces
        Map<String, Map<String, DataItem>> elements = elementsCheckingDigests(issuerSigned, get(mso, "valueDigests"));
        assertEquals(List.of(PhotoIdDataElements.NAMESPACE, PHOTO_ID_PROFILE_NAMESPACE).stream().sorted().toList(),
                elements.keySet().stream().sorted().toList());

        // org.iso.23220.1: every mandatory element, encoded as ISO/IEC TS 23220-4 Annex C requires
        Map<String, DataItem> core = elements.get(PhotoIdDataElements.NAMESPACE);
        assertTrue(core.keySet().containsAll(PhotoIdDataElements.MANDATORY));
        assertEquals(new ByteString(JPEG), core.get("portrait"));
        assertFullDate("2026-01-15", core.get("issue_date"));
        assertFullDate("2036-01-14", core.get("expiry_date"));
        assertFullDate("1985-04-29", get(core.get("birth_date"), "birth_date"));
        assertEquals(0, core.get("portrait_capture_date").getTag().getValue());
        assertEquals("2026-01-10T09:30:00Z", ((UnicodeString) core.get("portrait_capture_date")).getString());
        assertEquals(SimpleValue.TRUE, core.get("age_over_18"));
        assertEquals(new UnsignedInteger(41), core.get("age_in_years"));
        assertEquals(new UnicodeString("IN"), core.get("issuing_country"));
        // an element whose value is null is left out, with no digest
        assertFalse(core.containsKey("nationality"));

        // org.iso.23220.photoid.1: the profile's own elements, as text
        assertEquals(new UnicodeString("PID2154189532"), elements.get(PHOTO_ID_PROFILE_NAMESPACE).get("person_id"));
    }

    @Test
    public void should_rejectBeforeSigning_when_photoIdTemplateRendersAnInvalidValue() throws Exception {
        // the usual template mistake: "elementValue": "${ageOver18}" renders the text "true", not a boolean
        Map<String, Object> templateParams = holderParams();
        when(vcFormatter.format(templateParams)).thenReturn(renderedPhotoIdTemplate("Doe", "true"));

        CertifyException exception = assertThrows(CertifyException.class,
                () -> mDocCredential.createCredential(templateParams, TEMPLATE_NAME));

        assertEquals(ErrorConstants.MDOC_TEMPLATE_PROCESSING_FAILED, exception.getErrorCode());
        assertTrue(exception.getMessage(), exception.getMessage().endsWith("age_over_18 must be a boolean (true or false), not text or a number"));
        verify(coseSignatureService, never()).coseSign1(any());
    }

    /** The Photo ID template as Velocity renders it from a holder's data (validityInfo is filled in by Certify). */
    private static String renderedPhotoIdTemplate(String familyName, Object ageOver18) throws Exception {
        List<Map<String, Object>> core = new ArrayList<>();
        core.add(element("family_name", familyName));
        core.add(element("given_name", "John"));
        core.add(element("birth_date", Map.of("birth_date", "1985-04-29")));
        core.add(element("portrait", "data:image/jpeg;base64," + Base64.getEncoder().encodeToString(JPEG)));
        core.add(element("issue_date", "2026-01-15"));
        core.add(element("expiry_date", "2036-01-14"));
        core.add(element("issuing_authority", "Regional Identity Office, Bengaluru"));
        core.add(element("issuing_country", "IN"));
        core.add(element("age_over_18", ageOver18));
        core.add(element("age_in_years", 41));
        core.add(element("portrait_capture_date", "2026-01-10T15:00:00+05:30"));
        core.add(element("nationality", null));
        Map<String, Object> nameSpaces = new LinkedHashMap<>();
        nameSpaces.put(PhotoIdDataElements.NAMESPACE, core);
        nameSpaces.put(PHOTO_ID_PROFILE_NAMESPACE, List.of(element("person_id", "PID2154189532")));

        Map<String, Object> template = new LinkedHashMap<>();
        template.put("docType", PhotoIdDataElements.DOC_TYPE);
        template.put("validityInfo", Map.of("signed", "${_signed}", "validFrom", "${_validFrom}", "validUntil", "${_validUntil}"));
        template.put("nameSpaces", nameSpaces);
        return new ObjectMapper().writeValueAsString(template);
    }

    private static Map<String, Object> element(String identifier, Object value) {
        Map<String, Object> element = new LinkedHashMap<>();
        element.put("elementIdentifier", identifier);
        element.put("elementValue", value);
        return element;
    }

    /** The holder's proof key, as a did:jwk, which becomes the MSO device key. */
    private Map<String, Object> holderParams() throws Exception {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", Base64.getUrlEncoder().withoutPadding().encodeToString(coordinate(holderKey.getW().getAffineX())));
        jwk.put("y", Base64.getUrlEncoder().withoutPadding().encodeToString(coordinate(holderKey.getW().getAffineY())));
        Map<String, Object> params = new HashMap<>();
        params.put(Constants._HOLDER_ID, Constants.DID_JWK_PREFIX + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(new ObjectMapper().writeValueAsBytes(jwk)));
        return params;
    }

    /**
     * Each namespace's elements by identifier, checking that the SHA-256 of every IssuerSignedItemBytes is the
     * digest the MSO holds for its digestID (ISO/IEC 18013-5, 9.1.2.5).
     */
    private static Map<String, Map<String, DataItem>> elementsCheckingDigests(DataItem issuerSigned, DataItem valueDigests) throws Exception {
        Map<String, Map<String, DataItem>> elements = new HashMap<>();
        co.nstant.in.cbor.model.Map nameSpaces = (co.nstant.in.cbor.model.Map) get(issuerSigned, "nameSpaces");
        for (DataItem namespace : nameSpaces.getKeys()) {
            String name = ((UnicodeString) namespace).getString();
            co.nstant.in.cbor.model.Map digests = (co.nstant.in.cbor.model.Map) get(valueDigests, name);
            Map<String, DataItem> byIdentifier = new HashMap<>();
            for (DataItem itemBytes : ((Array) nameSpaces.get(namespace)).getDataItems()) {
                assertEquals(24, itemBytes.getTag().getValue());
                DataItem item = decode(((ByteString) itemBytes).getBytes());
                String identifier = ((UnicodeString) get(item, "elementIdentifier")).getString();
                assertArrayEquals(name + " " + identifier + " digest",
                        ((ByteString) digests.get(get(item, "digestID"))).getBytes(),
                        MessageDigest.getInstance("SHA-256").digest(encode(itemBytes)));
                byIdentifier.put(identifier, get(item, "elementValue"));
            }
            assertEquals(name + ": one digest per element", digests.getKeys().size(), byIdentifier.size());
            elements.put(name, byIdentifier);
        }
        return elements;
    }

    private static void assertFullDate(String expected, DataItem value) {
        assertEquals(1004, value.getTag().getValue());
        assertEquals(expected, ((UnicodeString) value).getString());
    }

    /** What keymanager's coseSign1 returns: a COSE_Sign1 over the payload, with the certificate in x5chain (33). */
    private CoseSignResponseDto coseSign1(CoseSignRequestDto request) throws Exception {
        byte[] payload = Base64.getUrlDecoder().decode(request.getPayload());
        co.nstant.in.cbor.model.Map protectedMap = new co.nstant.in.cbor.model.Map();
        protectedMap.put(new UnsignedInteger(1), new NegativeInteger(-7));
        byte[] protectedHeader = encode(protectedMap);
        Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(issuerKey.getPrivate());
        signer.update(sigStructure(protectedHeader, payload));

        co.nstant.in.cbor.model.Map unprotectedHeader = new co.nstant.in.cbor.model.Map();
        unprotectedHeader.put(new UnsignedInteger(33), new ByteString(issuerCertificate));
        Array cose = new Array();
        cose.add(new ByteString(protectedHeader));
        cose.add(unprotectedHeader);
        cose.add(new ByteString(payload));
        cose.add(new ByteString(signer.sign()));
        CoseSignResponseDto response = new CoseSignResponseDto();
        response.setSignedData(HexFormat.of().formatHex(encode(cose)));
        return response;
    }

    private static boolean verifies(PublicKey key, byte[] protectedHeader, byte[] payload, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(key);
        verifier.update(sigStructure(protectedHeader, payload));
        return verifier.verify(signature);
    }

    /** The COSE Sig_structure of a COSE_Sign1 without external data (RFC 9052, 4.4). */
    private static byte[] sigStructure(byte[] protectedHeader, byte[] payload) throws Exception {
        Array structure = new Array();
        structure.add(new UnicodeString("Signature1"));
        structure.add(new ByteString(protectedHeader));
        structure.add(new ByteString(new byte[0]));
        structure.add(new ByteString(payload));
        return encode(structure);
    }

    private PublicKey certificatePublicKey() throws Exception {
        return CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(issuerCertificate)).getPublicKey();
    }

    private static KeyPair p256KeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        return generator.generateKeyPair();
    }

    /** A certificate valid from yesterday, so that the MSO's signed timestamp (today 00:00:00Z) falls within it. */
    private static byte[] certificate(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=Test Photo ID Document Signer, C=IN");
        Instant notBefore = Instant.now().minus(Duration.ofDays(1));
        return new JcaX509v3CertificateBuilder(subject, BigInteger.ONE, Date.from(notBefore),
                Date.from(notBefore.plus(Duration.ofDays(730))), subject, keyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate()))
                .getEncoded();
    }

    private static byte[] coordinate(BigInteger value) {
        return BigIntegers.asUnsignedByteArray(32, value);
    }

    private static DataItem get(DataItem map, String key) {
        return ((co.nstant.in.cbor.model.Map) map).get(new UnicodeString(key));
    }

    private static DataItem decode(byte[] bytes) throws Exception {
        return new CborDecoder(new ByteArrayInputStream(bytes)).decode().get(0);
    }

    private static byte[] encode(DataItem item) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        new CborEncoder(out).encode(item);
        return out.toByteArray();
    }
}

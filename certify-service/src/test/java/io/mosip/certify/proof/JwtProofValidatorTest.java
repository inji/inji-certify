package io.mosip.certify.proof;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.ipfs.multibase.Multibase;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.exception.InvalidRequestException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.config.MDocConfig;
import io.mosip.certify.utils.MDocProcessor;
import io.mosip.kernel.signature.service.CoseSignatureService;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.*;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class JwtProofValidatorTest {

    private JwtProofValidator jwtProofValidator;

    Map<String, Object> proofConfiguration;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        jwtProofValidator = new JwtProofValidator();
        proofConfiguration = Map.of("jwt", Map.of(
                Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED, List.of("RS256", "ES256K", "EdDSA")));
        ReflectionTestUtils.setField(jwtProofValidator, "credentialIdentifier", "test-credential-id");
    }

    @Test
    void testValidateWithNullJwt() {

        String proofValue = null;


        boolean result = jwtProofValidator.validate("client-id", "nonce", proofValue, proofConfiguration);


        assertFalse(result, "Expected validation to fail for null JWT");
    }

    @Test
    void testValidateWithBlankJwt() {

        String proofValue = "";


        boolean result = jwtProofValidator.validate("client-id", "nonce",proofValue, proofConfiguration);


        assertFalse(result, "Expected validation to fail for blank JWT");
    }

    @Test
    void getProofType () {
        String proofType = jwtProofValidator.getProofType();
        assertNotNull(proofType);
        assertEquals("jwt", proofType);
    }

    @Test
    void testValidate_ValidJWT() throws Exception {
        String proofValue = createValidJWT();


        boolean result = jwtProofValidator.validate("test-client", "test-nonce", proofValue, proofConfiguration);

        assertTrue(result, "JWT should be valid");
    }

    @Test
    void testValidate_InvalidJWT() {
        String credentialProof ="invalid.jwt.token";

        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof, proofConfiguration);

        assertFalse(result, "Invalid JWT should fail validation");
    }

    @Test
    void should_returnDidJwkAndPublicJwk_when_proofHeaderCarriesJwk() throws Exception {
        // kid, use and alg describe the key but are not part of it, so none of them may reach cnf.jwk.
        // The DID is built from the header jwk as given, so it still carries them.
        RSAKey holderKey = new RSAKeyGenerator(2048)
                .keyID("holder-key-1")
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .generate();
        String proof = signProof(new JWSHeader.Builder(JWSAlgorithm.RS256).jwk(holderKey.toPublicJWK()),
                new RSASSASigner(holderKey));

        HolderKey result = jwtProofValidator.getHolderKey(proof);

        assertNotNull(result);
        assertTrue(result.did().startsWith("did:jwk:"));
        assertEquals(holderKey.toPublicJWK(),
                JWK.parse(Base64URL.from(result.did().substring("did:jwk:".length())).decodeToString()));
        assertEquals(Map.of(
                "kty", "RSA",
                "n", holderKey.getModulus().toString(),
                "e", holderKey.getPublicExponent().toString()), result.publicJwk());
    }

    @Test
    void should_returnProofDidAndPublicJwk_when_proofKidIsDidJwk() throws Exception {
        // Resolving a did:jwk sets the DID itself as the JWK's kid; that must not reach cnf.jwk.
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();
        String didJwk = "did:jwk:" + Base64URL.encode(holderKey.toPublicJWK().toJSONString());
        String proof = signProof(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(didJwk + "#0"),
                new ECDSASigner(holderKey));

        HolderKey result = jwtProofValidator.getHolderKey(proof);

        assertNotNull(result);
        assertEquals(didJwk + "#0", result.did());
        assertEquals(Map.of(
                "kty", "EC",
                "crv", "P-256",
                "x", holderKey.getX().toString(),
                "y", holderKey.getY().toString()), result.publicJwk());
    }

    @Test
    void should_returnProofDidAndPublicJwk_when_proofKidIsEd25519DidKey() throws Exception {
        // An Ed25519 did:key is base58btc(0xed 0x01 || raw public key), multibase-prefixed with 'z'.
        // The DID must stay did:key: deriving it from the JWK would turn it into a did:jwk.
        OctetKeyPair holderKey = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        byte[] rawPublicKey = holderKey.getDecodedX();
        byte[] multicodecKey = new byte[rawPublicKey.length + 2];
        multicodecKey[0] = (byte) 0xed;
        multicodecKey[1] = (byte) 0x01;
        System.arraycopy(rawPublicKey, 0, multicodecKey, 2, rawPublicKey.length);
        String didKey = "did:key:" + Multibase.encode(Multibase.Base.Base58BTC, multicodecKey);
        String proof = signProof(new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(didKey),
                new Ed25519Signer(holderKey));

        HolderKey result = jwtProofValidator.getHolderKey(proof);

        assertNotNull(result);
        assertEquals(didKey, result.did());
        assertEquals(Map.of(
                "kty", "OKP",
                "crv", "Ed25519",
                "x", holderKey.getX().toString()), result.publicJwk());
    }

    // The did:key vectors below are the ones DIDkeysProofManagerTest decodes. They are fixed rather than
    // generated: a random P-256 or secp256k1 key whose x or y starts with a 0x00 byte is decoded to a
    // 31-byte coordinate by DIDkeysProofManager, which would make these tests fail now and then.
    // getHolderKey reads only the proof header, so each proof is signed with a throwaway key.

    @Test
    void should_returnProofDidAndPublicJwkWithoutKid_when_proofKidIsP256DidKey() throws Exception {
        // The P-256 decoder sets the DID as the JWK's kid; it must not reach cnf.jwk.
        String didKey = "did:key:zDnaehKu2hNcmLBhd5iNkh3v6Q4ncq75fT4EXKMtietgzR1bZ";
        String proof = signProof(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(didKey),
                new ECDSASigner(new ECKeyGenerator(Curve.P_256).generate()));

        HolderKey result = jwtProofValidator.getHolderKey(proof);

        assertEquals(didKey, result.did());
        assertEquals(Map.of(
                "kty", "EC",
                "crv", "P-256",
                "x", "-wim35fhXPUsGq78EeP90JV1Fq0YvvYTbc_0kqhB6cQ",
                "y", "42YsvtOfjrHASU_mJTraPLeEuA-At3YsXQwbRZDpM_A"), result.publicJwk());
    }

    @Test
    void should_returnProofDidAndPublicJwk_when_proofKidIsSecp256k1DidKey() throws Exception {
        String didKey = "did:key:zQ3shsijT3Dmb494bwbLqj89Huo6QdYA8U6Xeo391cspCuC1s";
        // The JDK has no secp256k1, so the throwaway key and its signer use BouncyCastle.
        ECKey signingKey = new ECKeyGenerator(Curve.SECP256K1).provider(BouncyCastleProviderSingleton.getInstance()).generate();
        ECDSASigner signer = new ECDSASigner(signingKey);
        signer.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
        String proof = signProof(new JWSHeader.Builder(JWSAlgorithm.ES256K).keyID(didKey), signer);

        HolderKey result = jwtProofValidator.getHolderKey(proof);

        assertEquals(didKey, result.did());
        assertEquals(Map.of(
                "kty", "EC",
                "crv", "secp256k1",
                "x", "wldSvS-mIkLtxWUKTzH2bzpRc3r-lBeSu0FtqWBKiO4",
                "y", "omtLUrNAYHypnICk14EsyCbHmVQxBCsGf_n3Z2AAnQc"), result.publicJwk());
    }

    @Test
    void should_returnProofDidAndPublicJwk_when_proofKidIsRsaDidKey() throws Exception {
        String didKey = "did:key:z4MXj1wBzi9jUstyPx4gpGCHXGU6SZNCGaWDBktDPabqKE9pU9Y3D8GeMkeXipiM3MYJooZRkhi32m2CWdWVm1MTdYQs2pwtp92SPbLnp9eqDKTwCWNrvnqgsbJC9u6CvrXfUj1XeRZgSEkRxqoAjycSFyAsdrEP76d9NaRveKKabnNQ4y2NCBTY2q8c2tBP4HAGWVa4rMvsgmZY7zcoyf1rLnuAhG717cXdDrrWJnHXY3miMPfHvZbLhouoXcakRDRRnxPJYRCFHqqohSBeDxDqN1QKw77MFCDwz286bWpWWxS1mD4DZwQdBomoQgv5y1LyvndoxHJ4GukM2m8AzJvy5eibDufpJtva6F5cZMq3nKw4hJtnU";
        String proof = signProof(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(didKey),
                new RSASSASigner(new RSAKeyGenerator(2048).generate()));

        HolderKey result = jwtProofValidator.getHolderKey(proof);

        assertEquals(didKey, result.did());
        assertEquals(Map.of(
                "kty", "RSA",
                "n", "y6dYuJhvq1gPXDm2ulPepI5RO19Z9i0ZVrWkvebXEZ2R_gUXNpVk7zHa2K-Z_JEX1Vtnrgr9X2bBgsxU57PoPRQIMiVKbV-xPLEfmtuX7sFn2Oucj7_lqI0Nm3wPZ8X0nl5I-Wy-Lug5NGWghEtjbXzF2d2gHRtuZ72_MbYnMBT7qpkK7GizutCMBqmzXASdbxijkApteOe2cMqZprFcnoGSPV_sfD_1eQaFHNCMPJjYOm_L1Mx0M7vLMvbh3mNGlvxWN7gC7m5bgvn_TEBeKDi3OkMGmBbGXsVo7qcCxJrp_eIgahX3YtkzMsjD7CwM_A-H1vl8w_v0KtZZNbLpAw",
                "e", "AQAB"), result.publicJwk());
    }

    @Test
    void should_rejectProof_when_noDidCanBeDerivedFromTheHeader() throws Exception {
        // No embedded jwk and a kid that is neither did:jwk nor did:key: there is no DID to
        // return. This used to escape as a NoSuchElementException, a 500.
        RSAKey rsaJWK = new RSAKeyGenerator(2048).generate();
        String proof = signProof(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("key-1"),
                new RSASSASigner(rsaJWK));

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> jwtProofValidator.getHolderKey(proof));
        assertEquals(ErrorConstants.PROOF_HEADER_INVALID_KEY, exception.getErrorCode());
    }

    @Test
    void should_rejectProof_when_proofIsUnparsableJwt() {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> jwtProofValidator.getHolderKey("invalid.jwt.token"));
        assertEquals(VCIErrorConstants.INVALID_PROOF, exception.getErrorCode());
    }

    /**
     * Signs a minimal proof JWT. Only the header matters to key extraction, so the claims are not
     * the ones validate() requires.
     */
    private String signProof(JWSHeader.Builder header, JWSSigner signer) throws JOSEException {
        SignedJWT proof = new SignedJWT(header.type(new JOSEObjectType("openid4vci-proof+jwt")).build(),
                new JWTClaimsSet.Builder().issueTime(new Date()).build());
        proof.sign(signer);
        return proof.serialize();
    }

    private String createValidJWT() throws Exception {
        // Generate a 2048-bit RSA key pair
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Extract public key for embedding in the JWT header
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(rsaPublicJWK)  // Embed the public JWK
                .build();

        // Build JWT claims
        SignedJWT jwt = new SignedJWT(header, new com.nimbusds.jwt.JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("test-client")
                .claim("nonce", "test-nonce")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 60000)) // 1 min expiration
                .build());

        // Sign JWT using private key
        JWSSigner signer = new RSASSASigner(rsaJWK);
        jwt.sign(signer);

        return jwt.serialize();
    }

    private String createValidJWTWithDid(String issuer, Long expiryMillis, Boolean validDid ) throws Exception {
        // Generate a 2048-bit RSA key pair
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Extract public key
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        String didJWK;

        if(validDid)
            // Construct the did:jwk identifier
            didJWK  = "did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(rsaPublicJWK.toJSONString().getBytes()) + "#0";
        else
            didJWK = "did:jwk:invalid";

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .keyID(didJWK)  // Set kid as did:jwk
                .build();

        // Build JWT claims
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .claim("nonce", "test-nonce")
                .issueTime(new Date());

        if (issuer != null) {
            claimsBuilder.issuer(issuer);
        }

        if (expiryMillis != null) {
            claimsBuilder.expirationTime(new Date(System.currentTimeMillis() + expiryMillis));
        }

        SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());

        // Sign JWT using private key
        JWSSigner signer = new RSASSASigner(rsaJWK);
        jwt.sign(signer);

        return jwt.serialize();
    }

    @Test
    public  void testValidate_DIDJWK_ValidJWT_WithClientID_and_Expiry() throws Exception {
        String credentialProof = createValidJWTWithDid("test-client", 60000L, true);

        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof, proofConfiguration);

        assertTrue(result, "JWT should be valid");
    }

    @Test
    public  void testValidate_DIDJWK_ValidJWT_NoClientID_and_Expiry() throws Exception {
        String credentialProof = createValidJWTWithDid(null, 60000L, true);

        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof, proofConfiguration);

        assertTrue(result, "JWT should be valid");
    }

    @Test
    public  void testValidate_DIDJWK_ValidJWT_NoClientID_and_No_Expiry() throws Exception {
        String credentialProof = createValidJWTWithDid(null, null, true);

        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof, proofConfiguration);

        assertTrue(result, "JWT should be valid");
    }
    @Test
    public  void testValidate_DIDJWK_ValidJWT_WrongClientID() throws Exception {
        String credentialProof = createValidJWTWithDid("client-id-1", 600000L, true);
        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof, proofConfiguration);

        assertFalse(result, "Client id should match");
    }

    @Test
    public void testValidate_InvalidDID_JWK()  {
        String credentialProof = null;
        try {
            credentialProof = createValidJWTWithDid("test-client", 60000L, false);
        } catch (Exception e) {
            //do nothing here
        }
        //exception are handled by the validator logic presently
        assertFalse( jwtProofValidator.validate("test-client", "test-nonce", credentialProof, proofConfiguration));

    }

    @Test
    public void testValidate_InvalidJwt_MissingClaims() throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Extract public key for embedding in the JWT header
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(rsaPublicJWK)  // Embed the public JWK
                .build();

        // Build JWT claims
        SignedJWT jwt = new SignedJWT(header, new com.nimbusds.jwt.JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("test-client")
                .claim("nonce", "test-nonce")
                .expirationTime(new Date(System.currentTimeMillis() + 60000)) // 1 min expiration
                .build());

        // Sign JWT using private key
        JWSSigner signer = new RSASSASigner(rsaJWK);
        jwt.sign(signer);

        String credentialProof = jwt.serialize();
        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof, proofConfiguration);
        assertFalse(result, "Missing iat from jwt claims");
    }

    @Test
    public void testValidate_Es256_InvalidAlgException() throws ParseException, JOSEException {
        // Generate a valid ECKey with ES256
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Create a public JWK from the private JWK
        JWK publicJwk = ecJWK.toPublicJWK();

        // Create JWS Header with public JWK
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(publicJwk)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .build();

        // Build JWT Claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("clientId")
                .claim("nonce", "someNonce")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3600000)) // 1 hour from now
                .build();

        // Create and sign the JWT with the private EC key
        SignedJWT signedJWT = new SignedJWT(header, claims);
        JWSSigner signer = new ECDSASigner(ecJWK);
        signedJWT.sign(signer);

        // Serialize JWT
        String credentialProof = signedJWT.serialize();

        // Validate JWT
        boolean result = jwtProofValidator.validate("clientId", "someNonce", credentialProof, proofConfiguration);

        assertFalse(result, "No algorithm found exception");
    }

    @Test
    void testValidate_Es256WithNullHeaderType_InvalidAlgException() throws ParseException, JOSEException {
        // Generate a valid ECKey with ES256
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Create a public JWK from the private JWK
        JWK publicJwk = ecJWK.toPublicJWK();

        // Create JWS Header with public JWK
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(publicJwk)
                .type(null)
                .build();

        // Build JWT Claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("clientId")
                .claim("nonce", "someNonce")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3600000)) // 1 hour from now
                .build();

        // Create and sign the JWT with the private EC key
        SignedJWT signedJWT = new SignedJWT(header, claims);
        JWSSigner signer = new ECDSASigner(ecJWK);
        signedJWT.sign(signer);

        // Serialize JWT
        String credentialProof = signedJWT.serialize();

        // Validate JWT
        boolean result = jwtProofValidator.validate("clientId", "someNonce", credentialProof, proofConfiguration);

        assertFalse(result, "No algorithm found exception");
    }

    @Test
    void testValidate_Es256WithInvalidKeyId_InvalidAlgException() throws ParseException, JOSEException {
        // Generate a valid ECKey with ES256
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Create JWS Header with public JWK
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(null)
                .keyID(null)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .build();

        // Build JWT Claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("clientId")
                .claim("nonce", "someNonce")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3600000)) // 1 hour from now
                .build();

        // Create and sign the JWT with the private EC key
        SignedJWT signedJWT = new SignedJWT(header, claims);
        JWSSigner signer = new ECDSASigner(ecJWK);
        signedJWT.sign(signer);

        // Serialize JWT
        String credentialProof = signedJWT.serialize();

        // Validate JWT
        boolean result = jwtProofValidator.validate("clientId", "someNonce", credentialProof, proofConfiguration);

        assertFalse(result, "No algorithm found exception");
    }

    @Test
    void testValidate_Es256WithNonNullHeaderJwkAndKeyId_InvalidAlgException() throws ParseException, JOSEException {
        // Generate a valid ECKey with ES256
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Create a public JWK from the private JWK
        JWK publicJwk = ecJWK.toPublicJWK();

        // Create JWS Header with public JWK
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(publicJwk)
                .keyID(UUID.randomUUID().toString())
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .build();

        // Build JWT Claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("clientId")
                .claim("nonce", "someNonce")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3600000)) // 1 hour from now
                .build();

        // Create and sign the JWT with the private EC key
        SignedJWT signedJWT = new SignedJWT(header, claims);
        JWSSigner signer = new ECDSASigner(ecJWK);
        signedJWT.sign(signer);

        // Serialize JWT
        String credentialProof = signedJWT.serialize();


        // Validate JWT
        boolean result = jwtProofValidator.validate("clientId", "someNonce", credentialProof, proofConfiguration);

        assertFalse(result, "No algorithm found exception");
    }

    @Test
    void testValidate_ValidEd25519JWT() throws Exception {
        String keyId = "did:jwk:";
        String credentialProof = createValidEd25519JWT(keyId);

        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof, proofConfiguration);

        assertTrue(result, "Ed25519 JWT should be valid");
    }

    private String createValidEd25519JWT(String keyId) throws Exception {
        // Generate Ed25519 key pair
        OctetKeyPair edJWK = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID(UUID.randomUUID().toString())  // Use unique key ID
                .generate();

        // Create JWT header with Ed25519 algorithm and JWK
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .keyID(keyId + Base64.getUrlEncoder().withoutPadding().encodeToString(edJWK.toPublicJWK().toJSONString().getBytes(StandardCharsets.UTF_8)))
                .build();

        // Create JWT claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("test-client")
                .claim("nonce", "test-nonce")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 60000))
                .build();

        // Sign JWT with Ed25519
        SignedJWT jwt = new SignedJWT(header, claims);
        JWSSigner signer = new Ed25519Signer(edJWK);
        jwt.sign(signer);

        return jwt.serialize();
    }

    // ---------- EdDSA with an Ed448 key (RFC 8037), which Nimbus can't verify ----------

    @Test
    void should_acceptProof_when_holderKeyIsEd448() throws Exception {
        Ed448PrivateKeyParameters holderKey = new Ed448PrivateKeyParameters(new SecureRandom());

        String proof = ed448Proof(holderKey, holderKey.generatePublicKey().getEncoded());

        assertTrue(jwtProofValidator.validate("test-client", "test-nonce", proof, proofConfiguration));
    }

    @Test
    void should_rejectProof_when_ed448SignatureIsNotTheHolderKeys() throws Exception {
        Ed448PrivateKeyParameters holderKey = new Ed448PrivateKeyParameters(new SecureRandom());
        Ed448PrivateKeyParameters otherKey = new Ed448PrivateKeyParameters(new SecureRandom());

        // the header names the holder key, but the proof is signed with another one
        String proof = ed448Proof(otherKey, holderKey.generatePublicKey().getEncoded());

        assertFalse(jwtProofValidator.validate("test-client", "test-nonce", proof, proofConfiguration));
    }

    @Test
    void should_rejectProof_when_ed448KeyHasTheWrongLength() throws Exception {
        Ed448PrivateKeyParameters holderKey = new Ed448PrivateKeyParameters(new SecureRandom());

        // an Ed448 public key is 57 bytes; 32 is an Ed25519 key's size
        String proof = ed448Proof(holderKey, new byte[32]);

        assertFalse(jwtProofValidator.validate("test-client", "test-nonce", proof, proofConfiguration));
    }

    @Test
    void should_rejectProofWithoutThrowing_when_ed448KeyIsNotACurvePoint() throws Exception {
        Ed448PrivateKeyParameters holderKey = new Ed448PrivateKeyParameters(new SecureRandom());
        // 57 bytes, the right length, but not a point: the y coordinate (all ones) is larger than the field prime
        byte[] notAPoint = new byte[57];
        Arrays.fill(notAPoint, (byte) 0xFF);

        String proof = ed448Proof(holderKey, notAPoint);

        assertFalse(jwtProofValidator.validate("test-client", "test-nonce", proof, proofConfiguration));
    }

    @Test
    void should_buildAnEd448DeviceKey_when_mdocProofIsSignedWithEd448() throws Exception {
        Ed448PrivateKeyParameters holderKey = new Ed448PrivateKeyParameters(new SecureRandom());
        byte[] publicKey = holderKey.generatePublicKey().getEncoded();
        String proof = ed448Proof(holderKey, publicKey);

        // the proof is accepted, and its key becomes the mDL device key, as at issuance
        assertTrue(jwtProofValidator.validate("test-client", "test-nonce", proof, proofConfiguration));
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_holderId", jwtProofValidator.getHolderKey(proof).did());
        Map<String, Object> mso = new MDocProcessor(new ObjectMapper(), new MDocConfig(), mock(CoseSignatureService.class))
                .createMobileSecurityObject(mDocJson, new HashMap<>());
        Map<Object, Object> deviceKey = (Map<Object, Object>) ((Map<String, Object>) mso.get("deviceKeyInfo")).get("deviceKey");

        // ISO/IEC 18013-5, 9.1.5.2 (Table 22): kty OKP (1), crv Ed448 (7), x only
        assertEquals(Set.of(1, -1, -2), deviceKey.keySet());
        assertEquals(1, deviceKey.get(1));
        assertEquals(7, deviceKey.get(-1));
        assertArrayEquals(publicKey, (byte[]) deviceKey.get(-2));
    }

    @Test
    void should_rejectProofWithoutThrowing_when_eddsaProofCarriesAnEcKey() throws Exception {
        // the header claims EdDSA but names a P-256 key, which can't verify an EdDSA signature
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(ecKey.toPublicJWK())
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("test-client")
                .claim("nonce", "test-nonce")
                .issueTime(new Date())
                .build();
        String proof = header.toBase64URL() + "." + claims.toPayload().toBase64URL() + "." + Base64URL.encode(new byte[64]);

        assertFalse(jwtProofValidator.validate("test-client", "test-nonce", proof, proofConfiguration));
    }

    /** A proof JWT whose jwk header names the given Ed448 public key, signed with the given private key. */
    private String ed448Proof(Ed448PrivateKeyParameters signingKey, byte[] headerPublicKey) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(new OctetKeyPair.Builder(Curve.Ed448, Base64URL.encode(headerPublicKey)).build())
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("test-client")
                .claim("nonce", "test-nonce")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 60000))
                .build();
        String signingInput = header.toBase64URL() + "." + claims.toPayload().toBase64URL();
        Ed448Signer signer = new Ed448Signer(new byte[0]);
        signer.init(true, signingKey);
        byte[] input = signingInput.getBytes(StandardCharsets.US_ASCII);
        signer.update(input, 0, input.length);
        return signingInput + "." + Base64URL.encode(signer.generateSignature());
    }

    @Test
    void testValidate_Ed25519JWT_IllegalArgumentException() throws Exception {
        String credentialProof = createValidEd25519JWT("did:jwk: ");

        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof, proofConfiguration);

        assertFalse(result, "Invalid base64 encoded ID");
    }

    @Test
    void testValidateV2_NullJwt() {
        String credentialProof = null;
        boolean result = jwtProofValidator.validate("client-id", "nonce", credentialProof, Map.of("jwt", Map.of(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED, List.of("RS256"))));
        assertFalse(result, "Expected validation to fail for null JWT in validateV2");
    }

    @Test
    void testValidateV2_BlankJwt() {
        String credentialProof = "";
        boolean result = jwtProofValidator.validate("client-id", "nonce", credentialProof, Map.of("jwt", Map.of(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED, List.of("RS256"))));
        assertFalse(result, "Expected validation to fail for blank JWT in validateV2");
    }

    @Test
    void testValidateV2_UnsupportedAlgorithm() throws Exception {
        String credentialProof = createValidJWT();
        // proofConfiguration with unsupported algorithm
        Map<String, Object> proofConfig = Map.of("jwt", Map.of(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED, List.of("ES384")));
        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof, proofConfig);
        assertFalse(result, "Expected validation to fail for unsupported algorithm in validateV2");
    }

    @Test
    void testGetInstance_DidJwkKid() {
        JwtProofKeyManager manager = jwtProofValidator.getInstance("did:jwk:abc");
        assertNotNull(manager);
        assertTrue(manager instanceof DIDjwkProofManager);
    }

    @Test
    void testGetInstance_DidKeyKid() {
        JwtProofKeyManager manager = jwtProofValidator.getInstance("did:key:abc");
        assertNotNull(manager);
        assertTrue(manager instanceof DIDkeysProofManager);
    }

    @Test
    void testGetInstance_OtherKid() {
        JwtProofKeyManager manager = jwtProofValidator.getInstance("random:abc");
        assertNotNull(manager);
        assertTrue(manager instanceof DIDjwkProofManager);
    }

    @Test
    void testValidateV2_ValidJWT_RS256() throws Exception {
        String credentialProof = createValidJWT();
        Map<String, Object> proofConfig = Map.of("jwt", Map.of(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED, List.of("RS256")));
        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof, proofConfig);
        assertTrue(result, "Expected validation to succeed for valid RS256 JWT");
    }

    @Test
    void testValidateV2_ValidJWT_EdDSA() throws Exception {
        String keyId = "did:jwk:";
        String credentialProof = createValidEd25519JWT(keyId);
        Map<String, Object> proofConfig = Map.of("jwt", Map.of(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED, List.of("EdDSA")));
        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof, proofConfig);
        assertTrue(result, "Expected validation to succeed for valid Ed25519 JWT");
    }

    @Test
    void testValidateV2_InvalidJWT() {
        String credentialProof = "invalid.jwt.token";
        Map<String, Object> proofConfig = Map.of("jwt", Map.of(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED, List.of("RS256")));
        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof, proofConfig);
        assertFalse(result, "Expected validation to fail for invalid JWT in validateV2");
    }

    @Test
    void testValidateV2_MissingJwtConfig() throws Exception {
        String credentialProof = createValidJWT();
        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof, Map.of());
        assertFalse(result, "Expected validation to fail for missing jwt config in validateV2");
    }
}
package io.mosip.certify.proof;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.exception.InvalidRequestException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.*;

import static io.mosip.certify.core.constants.ErrorConstants.UNSUPPORTED_ALGORITHM;
import static io.mosip.certify.proof.DIDkeysProofManager.DID_KEY_PREFIX;

@Slf4j
@Component
public class JwtProofValidator implements ProofValidator {

    private static final String HEADER_TYP = "openid4vci-proof+jwt";
    private static final String DID_JWK_PREFIX = "did:jwk:";

    @Value("${mosip.certify.identifier}")
    private String credentialIdentifier;

    @Override
    public String getProofType() {
        return "jwt";
    }

    private static final Set<JWSAlgorithm> allowedSignatureAlgorithms;

    private static final Set<String> DEFAULT_REQUIRED_CLAIMS = Set.of("aud", "iat");

    static {
        allowedSignatureAlgorithms = new HashSet<>();
        allowedSignatureAlgorithms.addAll(List.of(JWSAlgorithm.Family.SIGNATURE.toArray(new JWSAlgorithm[0])));
    }

    @Override
    public boolean validate(String clientId, String cNonce, String proofJwt, Map<String, Object> proofConfiguration) {
        if(proofJwt == null || proofJwt.isBlank()) {
            log.error("Found invalid jwt in the credential proof");
            return false;
        }

        try {
            SignedJWT jwt = (SignedJWT) JWTParser.parse(proofJwt);
            Map<String, Object> jwtConfiguration;
            if(proofConfiguration.get("jwt") != null) {
                jwtConfiguration =(Map<String, Object>) proofConfiguration.get("jwt");
            } else {
                throw new InvalidRequestException(UNSUPPORTED_ALGORITHM);
            }
            List<String> algorithms = (List<String>) jwtConfiguration.getOrDefault(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED, List.of());
            validateHeaderClaims(jwt.getHeader(), algorithms);
            JwtProofKeyManager jpkm = getInstance(jwt.getHeader().getKeyID());
            JWK jwk = jpkm.getKeyFromHeader(jwt.getHeader())
                    .orElseThrow(() -> new InvalidRequestException(ErrorConstants.PROOF_HEADER_AMBIGUOUS_KEY));
            if(jwk.isPrivate()) {
                log.error("Provided key material contains private key! Rejecting proof.");
                throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY);
            }

            if (StringUtils.isEmpty(cNonce) && jwt.getJWTClaimsSet().getClaim("nonce") != null) {
                log.error("Nonce claim is present in proof JWT but no c_nonce is expected");
                return false;
            }

            JWTClaimsSet.Builder proofJwtClaimsBuilder = new JWTClaimsSet.Builder()
                    .audience(credentialIdentifier);
            if (!StringUtils.isEmpty(cNonce)) {
                proofJwtClaimsBuilder = proofJwtClaimsBuilder
                        .claim("nonce", cNonce);
            }

            // if the proof contains issuer claim, then it should match with the client id ref: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.2.1.1-2.2.2.1
            // https://github.com/openid/OpenID4VCI/issues/349
            Set<String> requiredClaims = new HashSet<>(DEFAULT_REQUIRED_CLAIMS);
            if(jwt.getJWTClaimsSet().getClaim("iss") != null) {
                proofJwtClaimsBuilder.issuer(clientId);
            }
            if(jwt.getJWTClaimsSet().getClaim("exp") != null) {
                requiredClaims.add("exp");
            }

            DefaultJWTClaimsVerifier claimsSetVerifier = new DefaultJWTClaimsVerifier(proofJwtClaimsBuilder.build(), requiredClaims);

            claimsSetVerifier.setMaxClockSkew(0);
            JWSKeySelector keySelector;
            if(JWSAlgorithm.ES256K.equals(jwt.getHeader().getAlgorithm())) {
                ECDSAVerifier verifier = new ECDSAVerifier((com.nimbusds.jose.jwk.ECKey) jwk);
                verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
                boolean verified = jwt.verify(verifier);
                claimsSetVerifier.verify(jwt.getJWTClaimsSet(), null);
                return verified;
            } else if (JWSAlgorithm.EdDSA.equals(jwt.getHeader().getAlgorithm()))
            {
                // EdDSA covers two curves (RFC 8037): Ed25519, which Nimbus verifies, and Ed448, which it doesn't.
                OctetKeyPair holderKey = jwk.toOctetKeyPair();
                boolean verified = Curve.Ed448.equals(holderKey.getCurve())
                        ? verifyEd448(jwt, holderKey)
                        : jwt.verify(new Ed25519Verifier(holderKey));
                claimsSetVerifier.verify(jwt.getJWTClaimsSet(), null);
                return verified;
            } else {
                keySelector = new JWSVerificationKeySelector(allowedSignatureAlgorithms,
                        new ImmutableJWKSet(new JWKSet(jwk)));
                ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
                jwtProcessor.setJWSKeySelector(keySelector);
                jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier(new JOSEObjectType(HEADER_TYP)));
                jwtProcessor.setJWTClaimsSetVerifier(claimsSetVerifier);
                jwtProcessor.process(proofJwt, null);
                return true;
            }
        } catch (InvalidRequestException e) {
            log.error("Invalid proof : {}", e.getErrorCode());
        } catch (ParseException e) {
            log.error("Failed to parse jwt in the credential proof", e);
        } catch (BadJOSEException | JOSEException e) {
            log.error("JWT proof verification failed", e);
        }
        return false;
    }


    /**
     * Verifies an EdDSA signature made with an Ed448 key (RFC 8037: Ed448 with an empty context) with
     * BouncyCastle, as Nimbus only verifies Ed25519. A key of the wrong length fails the proof.
     */
    private static boolean verifyEd448(SignedJWT jwt, OctetKeyPair holderKey) {
        byte[] publicKey = holderKey.getDecodedX();
        if (publicKey.length != Ed448PublicKeyParameters.KEY_SIZE) {
            log.error("Ed448 proof key has {} bytes instead of {}", publicKey.length, Ed448PublicKeyParameters.KEY_SIZE);
            return false;
        }
        Ed448Signer verifier = new Ed448Signer(new byte[0]);
        verifier.init(false, new Ed448PublicKeyParameters(publicKey, 0));
        byte[] signingInput = jwt.getSigningInput();
        verifier.update(signingInput, 0, signingInput.length);
        return verifier.verifySignature(jwt.getSignature().decode());
    }

    /**
     * @param proofJwt from the credential request.
     * @return the holder's key from the proof, as the DID the proof gave and as a JWK holding only its key members
     */
    @Override
    public HolderKey getHolderKey(String proofJwt) {
        JWSHeader header = parseProofHeader(proofJwt);
        JwtProofKeyManager keyManager = getInstance(header.getKeyID());
        // The DID is read from the header, not built from the JWK, so a did:key holder stays did:key.
        String did = keyManager.getDID(header)
                .orElseThrow(() -> new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY));
        JWK jwk = keyManager.getKeyFromHeader(header)
                .orElseThrow(() -> new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY));
        // The required members are the key itself: kty with n,e (RSA), crv,x,y (EC) or crv,x (OKP), as
        // hashed for a thumbprint (RFC 7638 §3.2). kid, use, alg, x5c and any private member are left out.
        return new HolderKey(did, new LinkedHashMap<>(jwk.getRequiredParams()));
    }

    /**
     * The proof header carries the holder's key, either as a jwk or as a did:jwk or did:key kid.
     * @throws InvalidRequestException INVALID_PROOF when the proof is not a parsable JWT
     */
    private JWSHeader parseProofHeader(String proofJwt) {
        try {
            return ((SignedJWT) JWTParser.parse(proofJwt)).getHeader();
        } catch (ParseException e) {
            log.error("Failed to parse jwt in the credential proof", e);
            throw new InvalidRequestException(VCIErrorConstants.INVALID_PROOF);
        }
    }

    private void validateHeaderClaims(JWSHeader jwsHeader, List<String> algorithms) {
        if(Objects.isNull(jwsHeader.getType()) || !HEADER_TYP.equals(jwsHeader.getType().getType()))
            throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_TYP);

        if(Objects.isNull(jwsHeader.getAlgorithm()) || !algorithms.contains(jwsHeader.getAlgorithm().getName()))
            throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_ALG);

        if ((Objects.isNull(jwsHeader.getKeyID()) && Objects.isNull(jwsHeader.getJWK()))
                ||
                (Objects.isNull(jwsHeader.getJWK()) && Objects.nonNull(jwsHeader.getKeyID()) &&
                        !(jwsHeader.getKeyID().startsWith(DID_KEY_PREFIX) || jwsHeader.getKeyID().startsWith(DID_JWK_PREFIX))))
            throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY);

        // both cannot be present, either one of them is only allowed
        if(Objects.nonNull(jwsHeader.getKeyID()) && Objects.nonNull(jwsHeader.getJWK()))
            throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_AMBIGUOUS_KEY);

        //TODO x5c and trust_chain validation
    }

    public JwtProofKeyManager getInstance(String kid) {
        if (kid == null || kid.startsWith(DID_JWK_PREFIX)) {
            return new DIDjwkProofManager();
        } else if (kid.startsWith("did:key:")) {
            return new DIDkeysProofManager();
        } else {
            return new DIDjwkProofManager();
        }
    }
}
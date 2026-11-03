package io.mosip.certify.proof;

import java.util.Map;

/**
 * The holder's key from one validated proof, in the two forms a credential binds to: the DID, which becomes
 * _holderId (ldp_vc credentialSubject.id, mso_mdoc deviceKey), and the public JWK, which becomes the
 * dc+sd-jwt cnf.
 * @param did the key as the proof gave it, did:jwk for a jwk header or a did:jwk kid, did:key for a did:key kid
 * @param publicJwk the key members of the JWK only, without kid or any other metadata
 */
public record HolderKey(String did, Map<String, Object> publicJwk) {
}

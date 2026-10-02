# DPoP (Demonstrating Proof of Possession) Support
Inji Certify accepts DPoP-bound access tokens at its credential endpoint, as defined in [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449). A DPoP-bound token is tied to a key held by the wallet: the authorization server records the thumbprint of that key in the token's `cnf.jkt` claim, and every request that presents the token must also carry a fresh proof signed with the same key.

Certify acts only as the **resource server** here. The authorization server (eSignet) decides whether a token is bound and issues it; Certify checks that the caller presenting the token holds the key it is bound to.

## Need for DPoP
1. **Stolen tokens are useless on their own:** A plain Bearer token works for whoever holds it. A DPoP-bound token also needs the wallet's private key, which never leaves the wallet.
2. **Proofs are tied to one request:** Each proof names the HTTP method and URL it was made for and the exact access token it accompanies, so it cannot be reused for a different request or with a different token.
3. **Replays are refused:** Each proof is single use and short-lived.
4. **Bearer clients keep working:** Tokens that are not bound are still accepted under the Bearer scheme, so wallets can move to DPoP one at a time.

## Solution Overview
Validation happens in `AccessTokenValidationFilter` and `DpopProofValidator`, and applies to every URL in `mosip.certify.authn.filter-urls` (by default only `/issuance/credential`).

1. **The wallet obtains a bound token:** The wallet sends a DPoP proof to eSignet's token endpoint. If the client is registered with `dpop_bound_access_tokens: true`, eSignet returns `token_type: DPoP` and puts the thumbprint of the wallet's key into the token's `cnf.jkt` claim.

2. **The wallet calls the credential endpoint:** It sends `Authorization: DPoP <access token>` together with a `DPoP: <proof JWT>` header. The proof is signed by the same key and carries `htm`, `htu`, `iat`, `jti` and `ath`.

3. **Certify validates the access token:** Signature, issuer, audience, expiry and the other claims are checked exactly as for a Bearer token. The scheme name is matched case-insensitively.

4. **Certify validates the proof:**

    | Check | Rule |
    |---|---|
    | Exactly one proof | One `DPoP` header, holding one JWT |
    | `typ` | `dpop+jwt` |
    | `alg` | One of `mosip.certify.dpop.allowed-algorithms`. MAC algorithms and `none` are always refused |
    | `jwk` | A public key embedded in the header; the signature must verify against it |
    | `htm` | Equals the request method |
    | `htu` | Equals `mosip.certify.domain.url` + the request path. Query and fragment are ignored; the path must match exactly |
    | `iat` | No more than `proof-max-age` seconds old, and no more than `clock-skew` seconds in the future |
    | `ath` | base64url SHA-256 of the access token being presented |
    | `cnf.jkt` | The access token's `cnf.jkt` equals the RFC 7638 thumbprint of the proof's `jwk` |
    | `jti` | Not used before by the same key. Checked last, so a rejected proof does not use up its `jti` |

5. **Certify refuses downgrades:** A token that carries `cnf.jkt` is refused under the Bearer scheme, because accepting it would remove the protection the binding provides. Under Bearer a `DPoP` header is ignored.

## Accepted Combinations
| Authorization scheme | Token | `DPoP` header | Result |
|---|---|---|---|
| `Bearer` | not bound | absent or present | accepted; the header is ignored |
| `Bearer` | bound (`cnf.jkt`) | any | `401 invalid_dpop_proof` |
| `DPoP` | bound | valid proof | accepted |
| `DPoP` | bound | missing, repeated or invalid | `401 invalid_dpop_proof` |
| `DPoP` | not bound | any | `401 invalid_dpop_proof` ("Access token is not DPoP-bound") |

## Error Responses
Every failure answers `401` with a `VCError` body and a `WWW-Authenticate` challenge in the scheme the caller used, so a DPoP client is never told to retry as Bearer. For `invalid_dpop_proof` the challenge also lists the accepted algorithms:

```text
WWW-Authenticate: DPoP error="invalid_dpop_proof", error_description="DPoP proof htu does not match the request URI", algs="ES256 ES384 ES512 RS256 PS256 EdDSA"
```
A problem with the access token itself (signature, expiry, issuer, audience) answers `invalid_token`, as it does for Bearer.

## Configuration Properties
| Property | Default | Purpose |
|---|---|---|
| `mosip.certify.dpop.allowed-algorithms` | `ES256,ES384,ES512,RS256,PS256,EdDSA` | Signature algorithms accepted on a proof, and advertised in `algs` |
| `mosip.certify.dpop.proof-max-age` | `60` | How old a proof's `iat` may be, in seconds |
| `mosip.certify.dpop.clock-skew` | `10` | Tolerance for wallet clock drift, applied on both sides of the window |
| `mosip.certify.dpop.jti.expire.seconds` | `120` | How long a used `jti` is remembered. **Must exceed `proof-max-age` + 2 × `clock-skew`**, since a proof with a future-dated `iat` stays fresh that long after first use; a shorter TTL lets it be replayed while still fresh |
| `mosip.certify.domain.url` | — | Public base URL the `htu` claim is compared against. Must be an absolute URL with a scheme |

### Required cache: `dpopJti`
Used `jti` values are kept in a cache named `dpopJti`. It must be declared in all three cache properties:

```properties
mosip.certify.cache.names=...,dpopJti
mosip.certify.cache.size={..., 'dpopJti': 10000 }
mosip.certify.cache.expire-in-seconds={..., 'dpopJti': ${mosip.certify.dpop.jti.expire.seconds} }
```

If the cache is missing, Certify refuses **every** DPoP request rather than silently skipping replay protection. When upgrading an existing deployment, add `dpopJti` to your own properties file; it is not picked up automatically.

`cache.size` applies only to the `simple` cache. At the default 120 second TTL, 10000 entries covers about 83 proofs per second; raise it for higher issuance rates.

### Multiple replicas
With `spring.cache.type=simple` each replica keeps its own list of used `jti` values, so a proof replayed against a different replica is accepted. Use `spring.cache.type=redis` when running more than one replica. Certify logs a warning at startup when the cache type is not distributed.

### Reverse proxy and `htu`
The wallet signs `htu` over the public credential endpoint it read from the issuer metadata, not the internal address Certify listens on. Certify therefore builds the expected value from `mosip.certify.domain.url`, never from the incoming request. That property must be the public URL, including `http://` or `https://`. A value without a scheme, such as `certify-nginx:80`, does not stop Certify from starting; it only makes DPoP requests fail.

## Authorization Server Requirements
- **eSignet 1.8 or later.** Older eSignet builds accept a DPoP proof at the token endpoint but ignore it and issue an unbound Bearer token, so every DPoP request to Certify fails with "Access token is not DPoP-bound".
- **Per-client binding.** The OIDC client must be registered with `additionalConfig.dpop_bound_access_tokens: true`, through `client-mgmt/client`. The older `client-mgmt/oidc-client` endpoint drops `additionalConfig`.
- **Algorithms.** eSignet 1.8 accepts only `RS256` and `PS256` on a DPoP proof at its token endpoint. Wallets should sign with one of those, because the same key signs the proofs sent to Certify.
- **Issuer.** `mosip.certify.authn.issuer-uri` must equal the `iss` of the tokens eSignet actually mints, as it does for Bearer.

## Testing
The mock-identity Postman collection has a DPoP branch with the full issuance flow and 26 RFC 9449 scenarios. See [README-mock-identity-dpop.md](../postman_collections/authorization_code_flow/data_provider_plugin/README-mock-identity-dpop.md) for environments, client registration and run order.

## Limitations
- **Credential endpoint only.** DPoP is enforced only on URLs listed in `mosip.certify.authn.filter-urls`.
- **Not enforced under the `local` profile.** `AccessTokenValidationFilter` is disabled when the `local` Spring profile is active, so neither Bearer nor DPoP tokens are validated there.
- **Pre-authorized code flow issues Bearer tokens only.** Certify's own token endpoint does not bind tokens to a key.
- **No server-provided nonce.** Certify does not issue `DPoP-Nonce` challenges (RFC 9449 section 9); proof freshness relies on `iat` and single-use `jti`.
- **Accepted algorithms are not published in metadata.** Certify has no protected-resource metadata document, so a wallet learns the accepted algorithms only from the `algs` parameter of a `401` challenge.

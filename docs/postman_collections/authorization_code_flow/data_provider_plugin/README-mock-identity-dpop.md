# Mock-identity collections: Bearer and DPoP

Two collections, **one environment each**:

| Postman name | File | What it does |
|---|---|---|
| `Inji Certify With Mock Identity` | `inji-certify-with-mock-identity.postman_collection.json` | Bearer credential issuance |
| `ENV Mock Identity Bearer` | `inji-certify-with-mock-identity.postman_environment.json` | environment for the above (and for the mDoc collection) |
| `Inji Certify With Mock Identity DPoP` | `inji-certify-with-mock-identity-dpop.postman_collection.json` | DPoP-constrained issuance (RFC 9449) |
| `ENV Mock Identity DPoP` | `inji-certify-with-mock-identity-dpop.postman_environment.json` | environment for the above |

They used to share one environment, and both wrote `csrf_token`, `access_token`, `transaction_id`, `oauth_details_key`, `oauth_details_hash` and `c_nonce` to it. Whichever collection ran last won, so a failure in one flow routinely came from the other flow's last run rather than from certify — most painfully via the client keys, which cannot be re-read or re-registered once lost. **Select the matching environment before running a collection.** Each collection checks this for itself: every environment carries `env_flavor` (`bearer` or `dpop`), and a collection-level pre-request script aborts the request if it does not match, naming the environment it found. Without that check a wrong-environment run would not fail at the first request — the two environments still share 20 variable names, so it would get some way in and write this flow's state into the wrong file. From **OIDC Client Mgmt** that costs a registered client: `pm.environment.set` *creates* `privateKey_jwk` in whichever environment is active, and eSignet can neither re-key a client nor hand the registered key back.

A hand-built environment with no `env_flavor` is refused too. Duplicating a shipped one carries the variable along, so only an environment assembled from scratch needs it added.

### The one value that still crosses over

`unbound_access_token` is a real eSignet token with **no `cnf.jkt`** — the fixture for *"a token that was never sender-constrained"*. Only the Bearer collection can mint it, because only `wallet-demo` is registered with `dpop_bound_access_tokens: false`, and its `6. Get Tokens V2` writes it into `ENV Mock Identity Bearer`.

One scenario needs it: **`Token binding / unbound token with a valid proof`**. To run that one, copy the value across by hand, once per token:

1. Run the Bearer collection's **VCI** folder against the same eSignet.
2. Copy `unbound_access_token` (the **Current** value) out of `ENV Mock Identity Bearer`.
3. Paste it into `unbound_access_token` in `ENV Mock Identity DPoP`.

The scenario throws with those instructions if the variable is empty. Every other scenario, including `ath is for a different token`, is self-contained.

## Run order

Clients first, if they are not registered yet: `Inji Certify With Mock Identity DPoP` → **OIDC Client Mgmt (DPoP)** for `dpop-wallet-demo`, and `Inji Certify With Mock Identity` → **OIDC Client Mgmt** for `wallet-demo`, once per deployment. Skip it against the local docker-compose stack — `setup-esignet.mjs` registers both clients there. See *Client registration*.

1. `Inji Certify With Mock Identity` with `ENV Mock Identity Bearer` selected → **VCI** folder, top to bottom. `2. Authorize / OAuthdetails request V2` must run before `3. Send OTP` — it sets `transaction_id`, `oauth_details_key` and `oauth_details_hash`.
2. Switch to `ENV Mock Identity DPoP`. `Inji Certify With Mock Identity DPoP` → **VCI (DPoP)** folder (steps 1–8, in order).
3. `Inji Certify With Mock Identity DPoP` → **DPoP scenarios**. These run on `access_token` (bound, from step 2) alone, except `unbound token with a valid proof` — see *The one value that still crosses over*.

Step 1 is needed only for that one scenario. Skip it and the other 25 still run.

## Switching deployments

Both environments ship pointing at a **local** deployment, and both carry the variables below — change them in whichever one you are running, and change these and no others — in particular leave `certifyUrl` and `audUrl` alone, for the reason below:

| Variable | Local (as shipped) | MOSIP released | MOSIP collab |
|---|---|---|---|
| `authServerUrl` | `http://localhost:8188/v1/esignet` | `https://esignet-mock.released.mosip.net/v1/esignet` | `https://esignet-mock.collab.mosip.net/v1/esignet` |
| `aud` | `http://localhost:8188/v1/esignet/oauth/v2/token` | `https://esignet-mock.released.mosip.net/v1/esignet/oauth/v2/token` | `https://esignet-mock.collab.mosip.net/v1/esignet/oauth/v2/token` |
| `mockIdentitySystemUrl` | `http://localhost:8182/v1/mock-identity-system` | `https://api.released.mosip.net/v1/mock-identity-system` | `https://api.collab.mosip.net/v1/mock-identity-system` |
| `internalUrl` | *(unused)* | `https://api-internal.released.mosip.net` | `https://api-internal.collab.mosip.net` |
| `relayingPartyId` | `mock-relying-party-id` | `mock-relying-party-id` | `mpartner-default-esignet` |

`internalUrl` and `partnerSecret` are needed only to register clients, not to run the flow — see *Registering clients on a hosted deployment* below. Both published environments ship `internalUrl` empty, and `partnerSecret` empty because it is deployment-specific and must not be committed.

### `certifyUrl` and `audUrl` track certify, not eSignet

Both describe **certify**. While certify runs locally they stay on `http://localhost:8091` no matter which eSignet you point at. Switching `authServerUrl` to a hosted host and dragging `audUrl` along with it is the single most common way to break this suite.

The Bearer collection's `8. Get Credential` signs the OpenID4VCI proof with `"aud": audUrl`, and `JwtProofValidator` compares it as an exact string against certify's `mosip.certify.identifier`. It must equal the `credential_issuer` value certify advertises:

```bash
curl -s $certifyUrl/.well-known/openid-credential-issuer \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['credential_issuer'])"
```

A wrong `audUrl` fails with `400 invalid_proof` — the same error as a wrong `iss`, a missing `iat`, or an unsupported `alg`, and indistinguishable from them without reading certify's log. A stale `c_nonce` is the one nearby failure that reports differently: `400 invalid_nonce`.

`http://certify-nginx:80` is certify's identifier only when certify itself runs **inside** the docker-compose network. Running certify as a host JVM it is `http://localhost:8091`, and the compose-internal hostname resolves nowhere.

### Pointing at a hosted certify

Moving certify itself off localhost is the one case where `certifyUrl` and `audUrl` *do* change — together, and to different values. `certifyUrl` carries the servlet path, `audUrl` does not: certify serves everything under `server.servlet.path=/v1/certify`, so a request to the bare host answers `404 Not Found` with `"path": "/nonce"`.

`configId` and `scope` are deployment-specific too. `FarmerCredential` and `mock_identity_vc_ldp` exist only on the mock stack, so both have to change with the issuer. Read the real values from the deployment rather than guessing:

```bash
curl -s $certifyUrl/.well-known/openid-credential-issuer | python3 -m json.tool
```

`credential_issuer` is what `audUrl` must equal exactly, and each entry under `credential_configurations_supported` gives a `configId` and its `scope`. Note the metadata is a `GET`; a `POST` there answers `403` from the CSRF filter.

Worked example — the land-registry deployment, verified end to end against released:

| Variable | Value |
|---|---|
| `certifyUrl` | `https://injicertify-landregistry.dev-int-inji.mosip.net/v1/certify` |
| `audUrl` | `https://injicertify-landregistry.dev-int-inji.mosip.net` |
| `configId` | `RegistrationReceiptCredential` |
| `scope` | `land_registry_vc_ldp` |

The DPoP environment has no `audUrl`: it derives `issuerIdentifier` from `certifyUrl` by stripping a trailing `/v1/certify`, which produces the same value. That derivation runs on every request, so setting `issuerIdentifier` by hand does not stick — and a deployment whose `credential_issuer` is not simply `certifyUrl` minus that suffix needs the collection-level pre-request changed, not the environment.

Check the hosted certify's own `authorization_servers` matches the eSignet you point `authServerUrl` at, and that its `mosip.certify.authn.issuer-uri` equals the `iss` of a real token from that eSignet — released mints `iss: https://esignet-mock.released.mosip.net`.

### Which deployments can run the DPoP collection

DPoP arrived in eSignet **1.8**, so this depends on the host's build:

| Deployment | eSignet | DPoP |
|---|---|---|
| `esignet-mock.released.mosip.net` | 1.8.0 | yes — `dpop_signing_alg_values_supported: ["RS256","PS256"]` |
| `esignet-mock.collab.mosip.net` | pre-1.8 | no — issues tokens with no `cnf.jkt` |
| local eSignet 1.8+ | 1.8+ | yes |

Against collab the **Bearer** collection works and every DPoP scenario fails by construction: without `cnf.jkt` certify can only ever answer "access token is not DPoP-bound".

Note the advertised algorithms are RSA only. A wallet key on an EC curve is rejected at the token endpoint, and the error does not name the algorithm.

### eSignet's issuer differs per deployment

Certify's `mosip.certify.authn.issuer-uri` must equal the token's `iss` claim exactly (`JwtIssuerValidator`), and hosted eSignets disagree about what that is:

| Deployment | `iss` in the access token |
|---|---|
| released | `https://esignet-mock.released.mosip.net` |
| collab | `https://esignet-mock.collab.mosip.net/v1/esignet` |

Collab's discovery document advertises the bare host while its tokens carry the `/v1/esignet` suffix; released's discovery and tokens agree. Neither rule generalises — decode a real token per environment and copy its `iss`. A mismatch gives `401 invalid_token` / "The access token is invalid."

## Client registration

Two OIDC clients are expected, differing only in `dpop_bound_access_tokens`:

| Env variable | Client id | `dpop_bound_access_tokens` | Used by |
|---|---|---|---|
| `clientId` | `wallet-demo` | `false` | Bearer flow; also the unbound-token fixture |
| `dpopClientId` | `dpop-wallet-demo` | `true` | DPoP flow |

Both authenticate with `private_key_jwt`, each with its own key, and each key now lives in its own environment — `dpop_privateKey_jwk` in `ENV Mock Identity DPoP`, `privateKey_jwk` in `ENV Mock Identity Bearer`. One collection can no longer overwrite the other's key.

Each is registered from its own collection: `dpop-wallet-demo` by **`OIDC Client Mgmt (DPoP)`** in the DPoP collection, `wallet-demo` by **`OIDC Client Mgmt`** in the Bearer one. Both **generate their own keypair** and write the private half back into the environment before sending, so nothing has to be present beforehand and nothing pasted in afterwards: register, then run the flow. Both `3. Create OIDC client` requests restore the previous private half if registration fails, rather than leaving the environment holding a key eSignet never saw — the new key is written before the request is sent, so without that a rejected registration costs you a working client and reports it only as `invalid_client` at the token step. `1. Authenticate (partner)` likewise clears `authToken` when authentication fails: client-mgmt answers "Full authentication is required to access this resource" at HTTP 200 for a stale token exactly as for a missing one, so a leftover value would look correctly populated while every registration silently failed. Against the local docker-compose stack `local-dev/dpop-test/setup-esignet.mjs` has already registered both and neither folder is needed.

Note the two collections name these requests alike: `3. Create OIDC client` exists in both folders and they post to **different endpoints**. The DPoP one posts to `client-mgmt/client`, **not** `client-mgmt/oidc-client`. The v1 `oidc-client` endpoint drops `additionalConfig`, so a client registered through it is never DPoP-bound — and nothing says so: registration succeeds, the token comes back without `cnf.jkt`, and every scenario then fails with "access token is not DPoP-bound".

They cannot share one key: eSignet enforces a unique public key per client and rejects the second registration with `duplicate_public_key`.

Note `wallet_private_key` is a **different** key again — it signs the DPoP proofs and is what `cnf.jkt` fingerprints. `dpop_privateKey_jwk` proves *which client* is calling; `wallet_private_key` proves *which sender* holds the token.

### Registering clients on a hosted deployment

Against a local eSignet container `client-mgmt` is unauthenticated: run requests 2–3 of the folder and skip request 1, which has nothing to talk to (`internalUrl` ships empty). On collab and released it is a Spring OAuth2 resource server, so registration needs a partner token first.

1. **`1. Authenticate (partner)`** → `{{internalUrl}}/v1/authmanager/authenticate/clientidsecretkey` with `appId: partner`, `clientId: mosip-pms-client`, and that deployment's secret. The token comes back in the **`Set-Cookie` header**, not the body — the body only carries `{status, message}`. The test script extracts it into `authToken`.
2. **`2. Get CSRF token`** → the body value, not the cookie (see *CSRF* below).
3. **`3. Create OIDC client`**.

The Bearer collection's **OIDC Client Mgmt** folder now mirrors this one request for request — `1. Authenticate (partner)`, `2. Get CSRF token`, `3. Create OIDC client` — and mints its own `authToken` into its own environment. Run whichever folder registers the client you need; neither borrows the other's token any more.

Three things reliably go wrong here:

- **The token goes in a header, not a cookie.** `Authorization: Bearer <token>` works; `Cookie: Authorization=<token>` is ignored and answers `Full authentication is required to access this resource` at HTTP 200. A malformed token is different again: HTTP 401 with an **empty body** and the real reason in the `WWW-Authenticate` response header. Read that header — it distinguishes `Malformed token` from `expired` from `insufficient_scope`, none of which appear in the body.
- **The token must carry `add_oidc_client`.** Decode it and check `scope`. A token from the wrong appId authenticates fine and still cannot register.
- **The partner secret is deployment-specific.** It is deliberately *not* committed: set `partnerSecret` in your own environment. A secret from one deployment gives `401 Unauthorized` on another, surfaced as `{"errorCode":"500","message":"401 Unauthorized: [no body]"}`.

### The registered public key cannot be changed

Neither update endpoint takes a `publicKey`, and there is no `GET` to read a registered key back. In eSignet 1.8.0 `PUT /client-mgmt/oidc-client/{client_id}` binds `ClientDetailUpdateRequest` and `PUT /client-mgmt/client/{client_id}` binds `ClientDetailUpdateRequestV3`; no field on either is the key.

So the moment a clientId exists it is welded to the key it was created with. If that private half is lost, the client is unusable and re-registering answers `duplicate_client_id`. **Use a new clientId** — there is no recovery path.

Both `Create …` requests generate a **fresh keypair on every run**, so the only copy of a registered client's private half is the one written into your environment. Two consequences: do not re-run them casually against a deployment where the client already exists, and do not click **Reset All** afterwards — that restores the committed demo keys over the working one. To keep a registered client, export the environment, or copy `dpop_privateKey_jwk` somewhere.

`additionalConfig` *is* updatable, so `dpop_bound_access_tokens` can be flipped in place on an existing client without touching its key. That is what **`4. Update OIDC`** is for.

### `4. Update OIDC`

`PUT /client-mgmt/client/{client_id}` — the same `client-mgmt/client` family as request 3, **not** `client-mgmt/oidc-client`. Only `ClientDetailUpdateRequestV3`, which that path binds, carries `additionalConfig`; sent to the v1 path the field is dropped silently, exactly as it is on create, and the client stops being DPoP-bound with nothing to say so.

It is a **full replacement, not a patch**. `logoUri`, `redirectUris`, `userClaims`, `authContextRefs`, `status`, `grantTypes`, `clientName` and `clientAuthMethods` all carry `@NotNull`/`@NotBlank`, so omitting one fails validation rather than leaving the stored value alone — the shipped body therefore restates request 3's values, and you change the one field you mean to change. `PATCH /client-mgmt/client/{client_id}` takes a partial body if you would rather not restate everything.

The request is optional; the VCI flow never needs it. Flipping `dpop_bound_access_tokens` to `false` through it is the cleanest way to watch every scenario fall back to `access token is not DPoP-bound`, and an easy thing to do by accident. The test script reports the value it sent to the Postman console rather than asserting it, so deliberately setting `false` does not show up as a failure.

## The committed keys are demo-only

`privateKey_jwk`, `dpop_privateKey_jwk`, `wallet_private_key` and `other_private_key` are complete RSA private keys, including `d`, `p` and `q`. They are committed to a public repository, so they are public from the moment they merge and must be treated as compromised.

They exist so the collections run against a local mock-identity stack with no setup. **Never register them with an authorization server that issues tokens for anything real**, and never reuse them outside this demo. To rotate, generate a fresh keypair, re-register the client with the new public half, and replace the private half here.

## Notes

- **CSRF.** eSignet 1.8 (Spring Security 6, BREACH protection) puts the raw token in the `XSRF-TOKEN` cookie and a masked token in the response body. `X-XSRF-TOKEN` must carry the **body** value; sending the cookie value gives `403 Forbidden` with an empty `path`.
- **DPoP nonce.** eSignet always rejects the first DPoP token request with `400 use_dpop_nonce` and a `DPoP-Nonce` header. Step 6 retries automatically with the nonce folded into the proof; this is expected, not a failure.
- **PKCE.** `codeVerifier`, `codeChallenge`, `codeChallengeMethod`, `code` and `client_assertion` are collection-scoped in both collections and deliberately absent from the environment. An environment variable of the same name would shadow the collection value — an empty one breaks PKCE with `unsupported_pkce_challenge_method`.
- **Initial vs Current value.** Postman stores two values per variable and `pm.environment.get()` reads only **Current**. Importing or syncing an environment routinely leaves Current blank while Initial still displays the data, so a variable looks populated and reads as `""`. Four variables are supplied by the environment file alone and no script ever rewrites them — `pmlib_code` (in both environments), and `dpop_lib`, `wallet_private_key`, `other_private_key` (DPoP only) — so for those a blank Current value never self-heals. The symptom is `JSONError: No data, empty input at 1:1` in a pre-request script, which does not name the variable. The client keys are not in that class: `dpop_privateKey_jwk` is written by the DPoP collection's `3. Create OIDC client` and `privateKey_jwk` by the Bearer collection's, so running those repairs a blank value. **Reset All** in the environment editor copies Initial into Current for every row. Note this also restores that environment's client key — `privateKey_jwk` in the Bearer environment, `dpop_privateKey_jwk` in the DPoP one — to the committed demo key, which will not match a client you registered yourself.
- **Same names, separate files.** Twenty variables exist in both environments — `csrf_token`, `access_token`, `transaction_id`, `oauth_details_key`, `oauth_details_hash`, `c_nonce`, `state`, the URLs, `configId`. That is not the collision the split removed: an environment is a document, only one is active at a time, and `pm.environment.set` writes to the active one, so two files holding a `csrf_token` each can never overwrite one another. The shared names are shared *configuration* (point one environment at a different certify and the other is unaffected) and per-flow runtime state that happens to be called the same thing. Prefixing them `bearer_` / `dpop_` would buy nothing once the files are separate — it protects a *shared* environment, which is what this stopped being — and the residual risk it would not cover, running against the wrong file, is what `env_flavor` covers instead.
- **Exports carry Initial values.** Exporting an environment writes the Initial column, so a shared export cannot capture a working hosted configuration and must never be used to check what someone was actually running.

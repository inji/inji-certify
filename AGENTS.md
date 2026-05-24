# AGENTS.md

This file describes the agent-relevant context for Inji Certify — its architecture, plugin model, key flows, and conventions that agents need to work effectively in this codebase.

---

## Project Identity

Inji Certify is an **OpenID4VCI 1.0 compliant Verifiable Credential issuance service**. It signs and issues credentials in W3C JSON-LD (`ldp_vc`), SD-JWT (`dc+sd-jwt`), and mock mDL (`mso_mdoc`) formats. It is a Spring Boot 3.2.3 / Java 21 multi-module Maven project licensed under MPL 2.0.

- **GitHub**: https://github.com/inji/inji-certify
- **Docs**: https://docs.inji.io/inji-certify/overview
- **API Docs**: https://mosip.stoplight.io/docs/inji-certify
- **Base URL** (local): `http://localhost:8090/v1/certify`

---

## Maven Modules

| Module | Role |
|---|---|
| `certify-parent` | Root POM; manages dependency versions and build plugins |
| `certify-service` | Spring Boot application — all controllers, services, credential generators, filters, DB entities |
| `certify-core` | Shared DTOs, constants, exception types, and service interfaces (`spi.*`) |
| `certify-integration-api` | Plugin SPI interfaces (`DataProviderPlugin`, `VCIssuancePlugin`, `AuditPlugin`) and DTOs published to plugin authors |

---

## Plugin Architecture (Critical to Understand)

Certify uses a **runtime plugin model**. Two plugin modes exist, set via `mosip.certify.plugin-mode`:

### `DataProvider` mode (recommended default)
- Plugin implements `certify-integration-api/.../spi/DataProviderPlugin`:
  ```java
  JSONObject fetchData(Map<String, Object> identityDetails) throws DataProviderExchangeException;
  ```
- Certify handles: templating (Apache Velocity), credential format construction, proof generation, signing.
- Plugin dependency is added to `certify-service/pom.xml` and loaded via Spring component scan (`mosip.certify.integration.scan-base-package`).

### `VCIssuance` mode (proxy/pass-through)
- Plugin implements `certify-integration-api/.../spi/VCIssuancePlugin` — returns a fully signed VC itself.
- Certify acts as an OpenID4VCI proxy. Used when integrating with pre-existing VC stacks (e.g., MOSIP IDA, Sunbird RC).

### Plugin Loading at Runtime (Docker/Helm)
- Plugin JARs can be mounted into the container's `loader_path/certify/` directory — no rebuild needed.
- `certify-service-with-plugins` image pre-bundles mock plugins.

---

## Credential Formats

| Format | Class | Notes |
|---|---|---|
| `ldp_vc` | `W3CJsonLD` | JSON-LD with linked-data proofs, supports revocation |
| `dc+sd-jwt` | `SDJWT` | Selective Disclosure JWT (renamed from `vc+sd-jwt` in OpenID4VCI 1.0) |
| `mso_mdoc` | `MDocCredential` | Mock only; full implementation pending |

`CredentialFactory` selects the right class based on `credentialFormat` in the `credential_config`.

---

## Proof Generation

`ProofGeneratorFactory` selects a proof generator from the `signatureCryptoSuite` in `credential_config`. Supported suites: `Ed25519Signature2018/2020`, `EcdsaSecp256r1Signature2019`, `EcdsaSecp256k1Signature2019`, `EcdsaKoblitzSignature2016`, `RsaSignature2018`, `ecdsa-rdfc-2019`, `ecdsa-jcs-2019`, `eddsa-rdfc-2022`, `eddsa-jcs-2022`.

---

## Key Controllers and Endpoints

| Controller | Prefix | Purpose |
|---|---|---|
| `VCIssuanceController` | `/issuance/credential` | Core VC issuance (OpenID4VCI 1.0 — single unified endpoint) |
| `NonceController` | `/nonce` | Dedicated `POST /nonce` endpoint for c_nonce generation (OpenID4VCI 1.0; no longer returned in token response) |
| `WellKnownController` | `/.well-known/` | Issuer metadata, DID document, JWKS |
| `CredentialConfigController` | `/credential-configurations` | CRUD for credential type configs |
| `OAuthController` | `/oauth/` | Token issuance and IAR (Interactive Auth Request) |
| `PreAuthorizedCodeController` | `/credential-offer-data/`, `/pre-authorized-data/` | Pre-auth code flow |
| `CredentialStatusController` | `/credentials/status`, `/credentials/status-list/{id}` | VC revocation/suspension |
| `CredentialLedgerController` | `/ledger-search` | Search issued credentials |
| `RenderingTemplateController` | `/rendering-template` | SVG/HTML templates for credential display |
| `SystemInfoController` | `/system-info/certificate` | Fetch signing certificates (key export) |

> **Note:** The vd11 and vd12 versioned issuance endpoints (`/issuance/vd11/credential`, `/issuance/vd12/credential`) and `CredentialConfigControllerV2` have been removed as part of the OpenID4VCI 1.0 cleanup.

---

## Core Service Flow (DataProvider mode)

```
Client → VCIssuanceController → CertifyIssuanceServiceImpl
  → AccessTokenValidationFilter (JWT validation against AuthZ server JWKS)
  → CredentialRequestValidator (format-specific: LdpVc / SdJwt / MsoMdoc)
  → DataProviderPlugin.fetchData()
  → VelocityTemplatingEngine (Velocity template from credential_config)
  → CredentialFactory.createCredential()
  → [Optional] StatusListCredentialService.addCredentialStatus()  ← revocation
  → ProofGeneratorFactory → ProofGenerator.addProof()
  → CredentialLedgerService.save()  ← if ledger enabled
  → return CredentialResponse
```

---

## Database Schema

PostgreSQL (`inji_certify` DB, `certify` schema). Key tables:

| Table | Purpose |
|---|---|
| `credential_config` | Registered credential types and their issuance config |
| `ledger` | Audit log of every issued credential |
| `status_list_credential` | BitstringStatusList VCs for revocation |
| `status_list_available_indices` | Index pool for status list slots |
| `credential_status_transaction` | Per-credential status change events |
| `rendering_template` | SVG/HTML templates referenced by DIDs |
| `key_alias`, `key_store`, `ca_cert_store` | MOSIP key manager tables |

A `StatusListUpdateBatchJob` runs every minute to re-sign updated status list credentials.

---

## Configuration Properties (Most Important)

```properties
# Plugin selection
mosip.certify.plugin-mode=DataProvider          # or VCIssuance
mosip.certify.integration.data-provider-plugin=MockCSVDataProviderPlugin
mosip.certify.integration.scan-base-package=io.mosip.certify.mock.integration

# AuthZ server (e.g., eSignet)
mosip.certify.authorization.url=http://localhost:8088
mosip.certify.authn.issuer-uri=...
mosip.certify.authn.jwk-set-uri=...

# Issuer identity
mosip.certify.domain.url=http://localhost:8090
mosip.certify.data-provider-plugin.did-url=did:web:...

# DB
spring.datasource.url=jdbc:postgresql://localhost:5432/inji_certify?currentSchema=certify

# Credential status (revocation)
mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes={'revocation'}
mosip.certify.issuer.ledger-enabled=true
```

---

## Caching

Certify uses Spring Cache with either `simple` (in-memory) or Redis backend. Cache names:
`userinfo`, `vcissuance`, `templatecache`, `certificatedatacache`, `credentialConfig`, `renderTemplate`, `jwks`, `preAuthCodeCache`, `credentialOfferCache`, `issuerMetadataCache`.

Switch to Redis by setting `spring.cache.type=redis` and configuring `spring.data.redis.*`.

---

## Key Design Conventions

- All property names use the `mosip.certify.*` namespace.
- Credential config validation is done at the API level (`CredentialConfigController`) and enforced again at issuance time.
- `didUrl` in `credential_config` can differ from `mosip.certify.data-provider-plugin.did-url` — the former is per-credential-type, the latter is the issuer-level DID.
- Velocity templates are stored in DB (`rendering_template` table) and referenced by UUID in `credential_config`.
- The `kid` prefix in SD-JWT (`dc+sd-jwt`) credentials is configurable via `mosip.kernel.keymanager.signature.kid.prepend`.
- c_nonce is **no longer returned in the access token response** (OpenID4VCI 1.0); clients must fetch it explicitly via `POST /nonce` (`NonceController` / `NonceServiceImpl`).
- DID document is auto-generated at `/.well-known/did.json` — copy and host it externally for VC verification.

---

## External Dependencies

- **eSignet** (or compatible OIDC server): acts as the OAuth 2.0 authorization server.
- **MOSIP Key Manager**: signs VCs via HSM/SoftHSM; key config in `mosip.kernel.keymanager.*`.
- **digital-credential-plugins** repo: provides mock and reference plugin implementations.

---

## References

- [Plugin interfaces](./certify-integration-api/src/main/java/io/mosip/certify/api/spi/)
- [Credential format classes](./certify-service/src/main/java/io/mosip/certify/credential/)
- [Proof generators](./certify-service/src/main/java/io/mosip/certify/proofgenerators/) *(if present)*
- [Sample local config](./certify-service/src/main/resources/application-local.properties)
- [DB scripts](./db_scripts/)
- [Docker Compose quickstart](./docker-compose/docker-compose-injistack/README.md)
- [Local dev guide](./docs/Local-Development.md)
- [Credential config guide](./docs/Credential-Issuer-Configuration.md)
- [VCIssuance vs DataProvider](./docs/VCIssuance-vs-DataProvider.md)
- [SD-JWT support](./docs/SD-JWT-Support.md)
- [VC Revocation](./docs/VC-Revocation-Support.md)

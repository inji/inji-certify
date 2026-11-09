# Changes in release 0.11.0

## Removal of  Artifactory dependency

```text
artifactory_url_env - this field is removed from configure_start.sh to remove dependency on artifactory
any new plugin to be added can be added by volume mount to loader_path

is_glowroot_env - this field is removed from configure_start.sh to remove dependency on glowroot apm



```
moved client.zip to build time dependency in dockerfile - addition of new hsm-client zip can be done by adding it to volume mount in docker-compose or helm charts with same structure as [client.zip](https://raw.githubusercontent.com/mosip/artifactory-ref-impl/v1.3.0-beta.1/artifacts/src/hsm/client.zip)

---

# Changes in release 0.12.0

## Restructure of credential_template table

Step-by-Step Migration guide for upgrade from 0.11.0 to 0.12.0 is available at [Migration Guide](./Migration_Guide_0.11.0_To_0.12.0.md)

---

# Changes in release 1.0.0-rc.1

## Velocity upgraded from 1.7 to 2.4.1: template behaviour changes

Credential templates (`vc_template`) are now rendered with Velocity 2.4.1. This fixes CVE-2020-13936.

**1. `#if` treats empty values as false**

| `phone` value | Before (1.7) | After (2.4.1) |
|---|---|---|
| `"+91..."` | included | included |
| `""` | `"phone": ""` included | **omitted** |
| null | omitted | omitted |

If a field must always appear, use `#if($var || $var == '')`, or drop the `#if` and use `$!{var}`.

**2. Loop variables renamed**

Replace `$velocityCount` with `$foreach.count`, and `$velocityHasNext` with `$foreach.hasNext`.

**3. Reflection blocked**

`SecureUberspector` is enabled. Templates can no longer call methods on classes like `Class`, `ClassLoader`, `Runtime` or `System`, so `$x.getClass().forName(...)` no longer works. Normal field access and the `$_dateTool` and `$_esc` tools are unaffected.

## Credential configuration metadata attributes are mandatory

`cryptographicBindingMethodsSupported`, `proofTypesSupported` and `signatureAlgo` are now mandatory in the Add (`POST /credential-configurations`) and Update (`PUT /credential-configurations/{credentialConfigKeyId}`) requests, for every credential format. A request that leaves one out, sends it as `null` or sends it empty is rejected, and nothing is filled in from the deployment properties any more. In particular, an `ldp_vc` configuration without `signatureAlgo` no longer takes the first algorithm declared for its crypto suite. `signatureAlgo` is mandatory in DataProvider plugin mode only: in VCIssuance plugin mode the plugin signs the credential, so it is optional, but a value that is sent is validated in both modes.

| Format | Plugin mode | `signatureAlgo` | `signatureCryptoSuite` | `credential_signing_alg_values_supported` |
|---|---|---|---|---|
| `ldp_vc` | DataProvider | Required | Required | The suite, e.g. `["Ed25519Signature2020"]` |
| `ldp_vc` | VCIssuance | Not required, validated if sent | Required | The suite, e.g. `["Ed25519Signature2020"]` |
| `mso_mdoc` | DataProvider | Required | Not required, ignored and not stored | COSE number of the algorithm, e.g. `[-7]` for `ES256` |
| `mso_mdoc` | VCIssuance | Not required, validated if sent | Not required, ignored and not stored | COSE number if set, e.g. `[-7]`. Omitted if null. |
| `dc+sd-jwt` | DataProvider | Required | Must not be sent (the request is rejected) | The algorithm, e.g. `["ES256"]` |
| `dc+sd-jwt` | VCIssuance | Not required, validated if sent | Must not be sent | The algorithm if set. Omitted if null. |

The plugin mode comes from `mosip.certify.plugin-mode`, not from the request.

`credentialSigningAlgValuesSupported` is no longer part of the request; a request that still sends it is rejected with `invalid_request` as an unrecognised field. What the credential issuer metadata advertises in `credential_signing_alg_values_supported` is derived from the configuration instead, so it is always what the credential is signed with:

- `ldp_vc` advertises its crypto suite, for example `Ed25519Signature2020`, as OpenID4VCI 1.0 Appendix A.1.2.2 requires ([#1110](https://github.com/inji/inji-certify/issues/1110)), where it previously advertised a JWS algorithm such as `EdDSA`.
- `dc+sd-jwt` advertises its `signatureAlgo`, and `mso_mdoc` the COSE identifier of its `signatureAlgo`, as before.

Nothing is resolved from the properties for it any more. Existing configurations advertise their own signing algorithm (or crypto suite for `ldp_vc`) without being re-submitted.

`mso_mdoc` is signed with `signatureAlgo` alone, so it now requires `signatureAlgo` in DataProvider plugin mode (optional in VCIssuance mode), and `signatureCryptoSuite` is optional. If one is sent for `mso_mdoc`, its value is not validated, and it is not stored.

**Action for existing automation:** every Update request must send both attributes, and `signatureAlgo` in DataProvider plugin mode, even one that only changes an unrelated field such as the display name. This includes configurations created before these attributes were stored. `credentialSigningAlgValuesSupported` must be removed from every request body.

See [Credential Issuer Configuration](./Credential_Issuer_Configuration.md) for the validation rules.

---

# Changes in release 1.0.0-rc.2

## `dc+sd-jwt` credentials carry the holder key as `cnf.jwk`

An issued `dc+sd-jwt` credential now carries the holder's public key in `cnf.jwk` ([RFC 7800 §3.2](https://www.rfc-editor.org/rfc/rfc7800.html#section-3.2)), where it previously carried a DID in `cnf.kid` ([#1141](https://github.com/inji/inji-certify/issues/1141)). `cnf.jwk` holds only the key members (`kty` with `n`, `e` for RSA, `crv`, `x`, `y` for EC, or `crv`, `x` for OKP), never `kid`, `use`, `alg` or a private member:

```diff
- "cnf": { "kid": "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2Iiwi..." }
+ "cnf": { "jwk": { "crv": "P-256", "kty": "EC", "x": "...", "y": "..." } }
```

Proofs are accepted as before: the holder key can still be sent as a `jwk` header, or as a `did:jwk` or `did:key` `kid`.

`cryptographic_binding_methods_supported` describes how the key appears in the issued credential ([OID4VCI 1.0 §12.2.4](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#section-12.2.4)), not which proofs are accepted. So `dc+sd-jwt` now advertises `jwk` only.

**Action for existing deployments:** set the `dc+sd-jwt` entry of `mosip.certify.credential-config.cryptographic-binding-methods-supported` to `{'jwk'}`.

**Action for existing credential configurations:** The upgrade script rewrites stored `dc+sd-jwt` configurations to `["jwk"]`.

Upgrading from 1.0.0-rc.1: re-run `0.14.0_to_1.0.0_upgrade.sql` (`CURRENT_VERSION=0.14.0`, `UPGRADE_VERSION=1.0.0` in `upgrade.properties`). It is safe to re-run.

## `mso_mdoc` credentials follow ISO/IEC 18013-5 for the MSO and the mDL data elements

Certify now builds the Mobile Security Object and encodes the mDL data elements as ISO/IEC 18013-5 requires ([#1147](https://github.com/inji/inji-certify/issues/1147)). In DataProvider plugin mode:

- **Digests:** the value digests use `mosip.certify.mdoc.digest-algorithm` (default `SHA-256`), the algorithm the MSO declares; they were always SHA-256 before. Only `SHA-256`, `SHA-384` and `SHA-512` are accepted (9.1.2.5), and any other value stops Certify at startup.
- **digestIDs:** each issued mdoc gets random digest IDs, unique within each namespace (9.1.2.4). A `digestID` in the template is ignored, so it can be left out.
- **validityInfo:** `signed`, `validFrom` and `validUntil` must be the placeholders `${_signed}`, `${_validFrom}` and `${_validUntil}`. A template that writes a date instead fails issuance with `mdoc_template_processing_failed`. `signed` is the start (00:00:00Z) of the UTC day of issuance, which reduces timestamp precision but does not guarantee unlinkability. `validFrom` is the same time, or the start of the mDL `issue_date` if that is later. `validUntil` is `mosip.certify.mdoc.validity-period-years` (default 2) after `validFrom`. A validity period below 1 year stops Certify at startup.
- **Full-dates:** in the `org.iso.18013.5.1` namespace, only `birth_date`, `issue_date`, `expiry_date` and the `issue_date` / `expiry_date` inside each `driving_privileges` entry are encoded as full-dates (CBOR tag 1004) (7.2.1, 7.2.4). Any other value that looks like a date stays text, in every namespace.
- **Byte strings:** `portrait`, `signature_usual_mark` and every `biometric_template_xx` carry base64 or base64url text (a `data:` URI is accepted too), which Certify encodes as a byte string (7.2.2, 7.2.7). A value that is not base64 text fails issuance with `MDOC_PROOF_FAILED`.
- **Mandatory elements:** Add and Update reject an `org.iso.18013.5.1.mDL` template missing a Table 5 mandatory element when the template can be checked before rendering. Dynamic templates are checked at issuance instead. An mDL missing an element after rendering fails issuance with `mdl_mandatory_elements_missing`. See [Credential Issuer Configuration](./Credential_Issuer_Configuration.md).

**Action for existing deployments:** make sure `mosip.certify.mdoc.digest-algorithm` is `SHA-256`, `SHA-384` or `SHA-512`, and `mosip.certify.mdoc.validity-period-years` is at least 1.

**Action for existing `mso_mdoc` templates:**
- Replace any date written in `validityInfo` with its placeholder.
- Give `portrait`, `signature_usual_mark` and `biometric_template_xx` as base64 text.
- Outside the `org.iso.18013.5.1` namespace, tag a value that must be a full-date explicitly: `{"__cbor_tag": 1004, "__cbor_value": "2024-06-15"}`. It was tagged automatically before.
- Make sure an mDL template declares all 11 mandatory elements. A stored template is checked again on its next Update, and every mDL is checked at issuance.

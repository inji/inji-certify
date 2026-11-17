# Credential Configuration

This guide explains how to manage (add, update, view, and delete) credential configurations in the Inji Certify service. These configurations tell Inji Certify how to issue different types of Verifiable Credentials using various formats and settings.

## What is a Credential Configuration?

A credential configuration defines the rules and details for issuing a specific type of digital credential. For example, it specifies the format, signing method, and any templates or types needed for the credential.

## Why is this important?

Before Inji Certify can issue a new type of credential, you need to define its configuration using the API endpoints described below. Additionally, this configuration will be used in openid-credential-issuer metadata to help clients understand how to interact with the credential issuer. This is crucial for ensuring that the credentials are issued correctly and can be verified by other systems.

---

## Available API Endpoints

You can use these endpoints to manage your credential configurations:

1. **Add a New Configuration**
    - **POST** `/credential-configurations`
    - Use this to create a new credential configuration.
    - You must provide all required details in the request body.

2. **Get a Configuration by ID**
    - **GET** `/credential-configurations/{credentialConfigKeyId}`
    - Use this to view the details of a specific configuration.

3. **Update an Existing Configuration**
    - **PUT** `/credential-configurations/{credentialConfigKeyId}`
    - Use this to change the details of an existing configuration.

4. **Delete a Configuration**
    - **DELETE** `/credential-configurations/{credentialConfigKeyId}`
    - Use this to remove a configuration you no longer need.

---

## What Information Do You Need to Provide?

When adding or updating a configuration, you need to send a JSON object with details related to the credential format you are configuring. The required fields depend on the credential format (e.g., `ldp_vc`, `mso_mdoc`, `dc+sd-jwt`). For more details regarding the API fields and examples, refer to the [Inji Certify API docs](https://mosip.stoplight.io/docs/inji-certify).

---

## Configuration Properties

The Inji Certify uses several configuration properties to control how credential configurations work. These are typically set in your `application.properties` or `application.yml` file.

| Property Name                                                          | Description                                                               | Example Value                                                                                                                                                                                                                                                                                     |
|------------------------------------------------------------------------|---------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes` | List of supported credential status purposes. Default value 'revocation'. | `["suspension", "revocation"]`                                                                                                                                                                                                                                                                    |
| `mosip.certify.credential-config.cryptographic-binding-methods-supported` | Supported cryptographic binding methods per credential format.            | `{ 'ldp_vc': {'did:jwk','did:key'}, 'mso_mdoc': {'cose_key'},'dc+sd-jwt': {'jwk'} }`                                                                                                                                                                                                                         |
| `mosip.certify.credential-config.credential-signing-alg-values-supported` | Supported signing algorithms per crypto suite, used to validate the `signatureAlgo` of an `ldp_vc` configuration. | `{ 'RsaSignature2018': {'RS256'}, 'Ed25519Signature2018': {'EdDSA'}, 'Ed25519Signature2020': {'EdDSA'}, 'EcdsaKoblitzSignature2016': {'ES256K'}, 'EcdsaSecp256k1Signature2019': {'ES256K'}, 'EcdsaSecp256r1Signature2019': {'ES256'}, 'ecdsa-rdfc-2019': {'ES256'}, 'ecdsa-jcs-2019': {'ES256'}}` |
| `mosip.certify.credential-config.proof-types-supported`                | Supported proof types for credentials.                                    | `{'jwt': {'proof_signing_alg_values_supported': {'RS256', 'PS256', 'ES256', 'EdDSA'}}}`                                                                                                                                                                                                           |
| `mosip.certify.signature-algo.key-alias-mapper`                       | Maps signature algorithms to list of key-aliases in key_alias table.      | `{'EdDSA': {{'CERTIFY_VC_SIGN_ED25519', ''}, {'CERTIFY_VC_SIGN_ED25519', 'ED25519_SIGN'}}`                                                                                                                                                                                                        |

## Validations and Rules

**Note** : 
In case of VCIssuance plugin mode, `ldp_vc` and `mso_mdoc` formats are supported by credential-configurations endpoints. 
In case of DataProviderPlugin mode, `ldp_vc`, `mso_mdoc` and `dc+sd-jwt` formats are supported by credential-configurations endpoints.

Inji Certify checks your configuration for required fields and possible duplicates:

- **Required fields** depend on the credential format.
- **No duplicate configurations**: You cannot add two configurations with the same key details. For example, 
  - for `ldp_vc` format, combination of context & type should be unique. 
  - for `mso_mdoc` format, docType value should be unique.
  - for `dc+sd-jwt` format, sdJwtVct value should be unique.
- **`mso_mdoc` templates**: in DataProvider plugin mode, Add and Update check an `mso_mdoc` template, and issuance checks its rendered values before signing. See [`mso_mdoc` templates](#mso_mdoc-templates) for the rules.
- **Validation for `signatureCryptoSuite`, `signatureAlgo`, `keyManagerAppId`, `keyManagerRefId`**.
  - In DataProvider plugin mode, `signatureAlgo` is mandatory for every credential format, on Add and on Update. It is the algorithm the credential is signed with, and nothing is filled in for it from the properties: a request that leaves it out is rejected with the format's mandatory-fields code, `ldp_vc_mandatory_fields_missing`, `mso_mdoc_mandatory_fields_missing` or `dc_sd_jwt_mandatory_fields_missing`.
  - In VCIssuance plugin mode the plugin signs the credential, so `signatureAlgo` is optional. A value that is sent is validated as below, in both modes. An `mso_mdoc` or `dc+sd-jwt` configuration without `signatureAlgo` leaves `credential_signing_alg_values_supported` out of the credential issuer metadata; an `ldp_vc` one still advertises its crypto suite.
  - `ldp_vc`: `signatureCryptoSuite` is mandatory and must be declared in `mosip.certify.credential-config.credential-signing-alg-values-supported` (`unsupported_crypto_suite` otherwise), and `signatureAlgo` must be one of the algorithms declared for that suite (`unsupported_signature_algo` otherwise).
  - `mso_mdoc`: an mdoc's issuerAuth is signed with `signatureAlgo` alone, so `signatureCryptoSuite` is optional. If one is sent, its value is not validated, and it is not stored. The deployment must hold a signing key for `signatureAlgo` in `mosip.certify.signature-algo.key-alias-mapper` (`key_chooser_config_not_found` otherwise), and it must be `ES256`, the only algorithm supported for an mdoc's issuerAuth. `EdDSA`, `RS256` and `ES256K` are rejected with `unsupported_credential_signing_alg`.
  - `dc+sd-jwt`: the deployment must hold a signing key for `signatureAlgo` in `mosip.certify.signature-algo.key-alias-mapper` (`key_chooser_config_not_found` otherwise).
  - `keyManagerAppId` and `keyManagerRefId` must refer to the correct keys defined in `mosip.certify.signature-algo.key-alias-mapper`.
  - `mso_mdoc` in DataProvider plugin mode: Certify signs the MSO with the key `keyManagerAppId` and `keyManagerRefId` name, so they are mandatory and must be one of the pairs the key-alias-mapper gives for `signatureAlgo` (for `ES256`, `CERTIFY_VC_SIGN_EC_R1` / `EC_SECP256R1_SIGN` by default). Add and Update reject a configuration without them, or with another pair, with `key_chooser_app_ref_not_found`; there is no default key. A configuration stored without them is rejected on its next Update.
- **`signatureAlgo` and `signatureCryptoSuite` by format and plugin mode**.

  | Format | Plugin mode | `signatureAlgo` | `signatureCryptoSuite` | `credential_signing_alg_values_supported` |
  |---|---|---|---|---|
  | `ldp_vc` | DataProvider | Required | Required | The suite, e.g. `["Ed25519Signature2020"]` |
  | `ldp_vc` | VCIssuance | Not required, validated if sent | Required | The suite, e.g. `["Ed25519Signature2020"]` |
  | `mso_mdoc` | DataProvider | Required | Not required, ignored and not stored | COSE number of the algorithm, e.g. `[-7]` for `ES256` |
  | `mso_mdoc` | VCIssuance | Not required, validated if sent | Not required, ignored and not stored | COSE number if set, e.g. `[-7]`. Omitted if null. |
  | `dc+sd-jwt` | DataProvider | Required | Must not be sent (the request is rejected) | The algorithm, e.g. `["ES256"]` |
  | `dc+sd-jwt` | VCIssuance | Not required, validated if sent | Must not be sent | The algorithm if set. Omitted if null. |

  The plugin mode comes from `mosip.certify.plugin-mode`, not from the request.

- **What the credential issuer metadata advertises in `credential_signing_alg_values_supported`**.
  - It is derived from the credential configuration; the Add and Update requests no longer take a `credentialSigningAlgValuesSupported` list, and a request that still sends it is rejected with `invalid_request` as an unrecognised field, storing nothing. Each configuration advertises the one value it is signed with, so what is advertised can never differ from how the credential is signed.
  - `ldp_vc` advertises its `signatureCryptoSuite`, for example `Ed25519Signature2020` or `eddsa-rdfc-2022`, as OpenID4VCI 1.0 Appendix A.1.2.2 requires ([#1110](https://github.com/inji/inji-certify/issues/1110)). A JWS algorithm such as `EdDSA` stands for more than one suite, so a wallet could not act on it.
  - `dc+sd-jwt` advertises its `signatureAlgo`, for example `ES256`, and `mso_mdoc` advertises the COSE identifier of its `signatureAlgo`, `-7` for `ES256`.
  - Nothing is resolved from the properties for it, in the issuer metadata or the Get response. Existing configurations advertise their own signing algorithm (or crypto suite for `ldp_vc`) without being re-submitted.
- **Per-configuration selection of `cryptographicBindingMethodsSupported` and `proofTypesSupported`**.
  - Both are mandatory in the Add and Update Credential Configuration requests, and are always returned by the Get response. A request that leaves one out, sends it as `null` or sends it empty is rejected with `invalid_request`, naming the attribute.
  - The configuration properties above are the allow-list, and only the allow-list. A request can select from or narrow what the deployment declares; it can never exceed it, and nothing is filled in from the properties when a value is missing.
  - `cryptographicBindingMethodsSupported` is validated against the methods declared for the credential format in `mosip.certify.credential-config.cryptographic-binding-methods-supported`.
  - `proofTypesSupported` is validated against `mosip.certify.credential-config.proof-types-supported`. Each proof type must be declared there and must carry a non-empty `proof_signing_alg_values_supported`, which must be a subset of the algorithms declared for that proof type. `proof_signing_alg_values_supported` is the only recognised attribute within a proof type entry. A proof type sent as `null`, without `proof_signing_alg_values_supported`, or with an empty list is rejected with `invalid_request`.
  - For `mso_mdoc`, the proof key becomes the mDL device key, which must be an EC key on P-256, so `proof_signing_alg_values_supported` may only list `ES256` (ISO/IEC 18013-5, 9.1.3.4). Any other algorithm the deployment declares is rejected with `unsupported_proof_signing_alg`.
  - A deployment may declare a proof type with no proof signing algorithms. It still starts and serves requests; only a request naming that proof type is rejected.
  - On Update both are sent again and replace what is stored. Any valid selection may be changed to any other valid selection.
  - If several values across the attributes and the signing algorithm are invalid, all of them are reported together so the payload can be corrected in a single pass.
  - A value listed more than once, in either attribute or in a proof type's `proof_signing_alg_values_supported`, is stored once, in the order first given. The request is not rejected for it; for example, `["did:jwk", "did:jwk"]` is stored as `["did:jwk"]`.
  - Whatever is stored against a credential configuration is what the Get response returns and the credential issuer metadata advertises for it.
  - **Configurations created before these attributes were stored** need not be re-submitted. Where nothing is stored for the binding methods or proof types, the Get response and the issuer metadata keep resolving them from the properties as before.
  - **Upgrading existing automation:** every Update request must now send both attributes, and `signatureAlgo` in DataProvider plugin mode, even one that only changes an unrelated field such as the display name. A script or client that omits any of them receives an error. `credentialSigningAlgValuesSupported` must be removed from every request body.
  - An empty `cryptographicBindingMethodsSupported` or `proofTypesSupported` is rejected for now.
- **Purpose of `didUrl` in `credential_config`**:
  - `didUrl` in `credential_config` can be different from the issuer did url specified by the property `mosip.certify.data-provider-plugin.did-url`.
  - It is used to point to temporary `didUrl` which is specific to a VC type. The did document fetched from the `./well-known/did.json` endpoint can be copied and hosted on the credentialConfig didUrl.
  - **Example**: `mosip.certify.data-provider-plugin.did-url=did:mosip:12345`
  - `credential_config.didUrl=did:mosip:12345:driver_license`
  - In this case, the did document for `did:mosip:12345:driver_license` can be copied from `did:mosip:12345` and hosted on this url.
    
If you miss a required field or try to add a duplicate, Certify will return an error.

## `mso_mdoc` templates

In DataProvider plugin mode Certify builds and signs an `mso_mdoc` credential from the configuration's `vcTemplate`, following ISO/IEC 18013-5. Add and Update check the template itself; issuance checks the rendered values, before signing. These rules apply in DataProvider plugin mode only; in VCIssuance mode the plugin builds the credential.

### `validityInfo`

Every `mso_mdoc` template must have `validityInfo` with `signed`, `validFrom` and `validUntil` set to the strings `"${_signed}"`, `"${_validFrom}"` and `"${_validUntil}"`; Certify sets these dates at issuance (ISO/IEC 18013-5, 9.1.2.4). Add and Update reject a template that leaves out `validityInfo` or one of these fields, or writes anything else in it (a date, or an unquoted `${_signed}`), with `mdoc_template_processing_failed`, naming the field.
- A template that can only be read once Velocity renders it (a directive such as `#if`) is not checked at Add and Update; it fails issuance with the same error instead. A configuration stored before this check is checked on its next Update.
- Certify sets the three dates at issuance, as tdates in UTC without fractions of seconds (ISO/IEC 18013-5, 7.2.1 and 9.1.2.4):
  - `signed` is the start (00:00:00Z) of the UTC day of issuance, or the signing certificate's `notBefore` if that is later (on the day a signing key is generated or rotated). This reduces timestamp precision but does not guarantee unlinkability.
  - `validFrom` is the same time, or the start of the mDL `issue_date` if that is later; for an `issue_date` that is a date-time, the next 00:00:00Z at or after it.
  - `validUntil` is `mosip.certify.mdoc.validity-period-years` (at least 1) after `validFrom`.
- An mDL whose `signed` is outside the validity of the certificate in the MSO header after signing (the key was rotated in between) fails issuance with `MDOC_PROOF_FAILED`.

### `digestID`

`digestID` is optional and ignored: each issued mdoc gets random digest IDs, unique within each namespace (ISO/IEC 18013-5, 9.1.2.4).

### Mandatory mDL elements

An `mso_mdoc` configuration with docType `org.iso.18013.5.1.mDL` must declare every ISO/IEC 18013-5 (Table 5) mandatory data element in the `org.iso.18013.5.1` namespace of its template: `family_name`, `given_name`, `birth_date`, `issue_date`, `expiry_date`, `issuing_country`, `issuing_authority`, `document_number`, `portrait`, `driving_privileges` and `un_distinguishing_sign`. Otherwise Add and Update are rejected with `mdl_mandatory_elements_missing`, naming the missing elements.
- Only the element identifiers are checked, not their values, so a value may be an unquoted reference such as `"elementValue": ${drivingPrivileges}`. A template that can only be read once Velocity renders it is not checked: one with a directive such as `#if` or `#foreach`, or one where `nameSpaces`, the mDL namespace, its element list, an element or an element identifier is a reference such as `${nameSpaces}`, `${elements}` or `${element.id}`.
- An element identifier declared twice in the `org.iso.18013.5.1` namespace is rejected with `mdoc_template_processing_failed`.
- The check runs on Add and Update only; the rendered mDL is not checked at issuance. A configuration stored before this check is checked on its next Update.

### Dates in the mDL namespace

In the `org.iso.18013.5.1` namespace, `birth_date`, `issue_date`, `expiry_date` and the `issue_date` and `expiry_date` inside each `driving_privileges` entry are encoded as full-dates (CBOR tag 1004) when their value is a date (YYYY-MM-DD) (ISO/IEC 18013-5, 7.2.1 and 7.2.4). No other value is tagged as a date, whatever it looks like.
- The top-level `issue_date` and `expiry_date` may instead be a date-time, encoded as a tdate (CBOR tag 0) in UTC without fractions of seconds.
- `driving_privileges` must be an array of DrivingPrivilege entries (7.2.4): each a map with a text `vehicle_category_code`, an optional `issue_date` and `expiry_date`, and optional `codes`, a non-empty array of maps with a text `code` and an optional text `sign` and `value`. No other keys are allowed.
- A value of one of these elements that is not a date (or, for the top-level `issue_date` and `expiry_date`, a date-time), whether as text, another type or a different tag, fails issuance with `mdoc_template_processing_failed` before signing, and so does a `driving_privileges` value that breaks the structure above.

### Byte strings

`portrait`, `signature_usual_mark` and every `biometric_template_xx` (for example `biometric_template_face`) in the `org.iso.18013.5.1` namespace carry base64 or base64url text (a data URI such as `data:image/jpeg;base64,...` is accepted too), which Certify encodes as a byte string (ISO/IEC 18013-5, 7.2.2 and 7.2.7). `portrait` must be a JPEG or JPEG2000 image. A value that is not base64 text, or a `portrait` that is not a JPEG or JPEG2000 image (for example a PNG or an empty value), fails issuance with `mdoc_template_processing_failed` before signing.
- Byte strings are produced only in the `org.iso.18013.5.1` namespace. `__cbor_tag` can tag a date but cannot produce a byte string, so in any other namespace an image or other binary value is always encoded as text.

### Explicit CBOR tags

An `mso_mdoc` template may tag a value itself, for example `{"__cbor_tag": 1004, "__cbor_value": "2024-06-15"}`, which is how a full-date or tdate is written outside the `org.iso.18013.5.1` namespace. Add and Update reject a `__cbor_tag` that is not the integer `1004` (full-date) or `0` (tdate), with `mdoc_template_processing_failed`, naming where it is. At issuance, a value tagged `1004` must be a date (YYYY-MM-DD) and one tagged `0` an RFC 3339 date-time, or issuance fails with the same error.

---
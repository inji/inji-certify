-- 0.14.0 requires holder binding for every credential configuration. Give configurations without
-- holder binding (NULL) the 1.0.0 defaults; the steps below convert them to the 0.14.0 form.
UPDATE certify.credential_config
SET cryptographic_binding_methods_supported = CASE
        WHEN credential_format = 'mso_mdoc' THEN ARRAY['cose_key']
        ELSE ARRAY['did:jwk', 'did:key']
    END
WHERE cryptographic_binding_methods_supported IS NULL;

UPDATE certify.credential_config
SET proof_types_supported = '{"jwt": {"proof_signing_alg_values_supported": ["RS256", "ES256", "PS256", "EdDSA"]}}'::jsonb
WHERE proof_types_supported IS NULL;

UPDATE certify.credential_config
SET display = COALESCE((
    SELECT jsonb_agg(
                   CASE
                       WHEN elem->'logo' IS NOT NULL
                           AND (elem->'logo')::jsonb ? 'uri' THEN
                           jsonb_set(
                                   elem::jsonb,
                                   '{logo}',
                                   ((elem->'logo')::jsonb - 'uri')
                    || jsonb_build_object(
                        'url',
                        (elem->'logo')::jsonb -> 'uri'
                    )
                )
                       ELSE elem::jsonb
                       END
           )
    FROM jsonb_array_elements(display::jsonb) AS elem
), '[]'::jsonb)
WHERE display IS NOT NULL;

ALTER TABLE certify.credential_config
RENAME COLUMN claims TO credential_subject;
COMMENT ON COLUMN certify.credential_config.credential_subject IS 'Credential Subject: JSON object containing subject attributes schema.';

UPDATE certify.credential_config
SET credential_format = 'vc+sd-jwt'
WHERE credential_format = 'dc+sd-jwt';

DROP INDEX IF EXISTS certify.idx_vp_submission_response_code;
DROP INDEX IF EXISTS certify.idx_vc_submission_transaction_id;
DROP INDEX IF EXISTS certify.idx_ard_transaction_id;

DROP TABLE IF EXISTS certify.vp_submission;
DROP TABLE IF EXISTS certify.vc_submission;
DROP TABLE IF EXISTS certify.authorization_request_details;

UPDATE certify.credential_config
SET proof_types_supported = '{}'::jsonb
WHERE proof_types_supported = '{"jwt": {"proof_signing_alg_values_supported": ["RS256", "ES256", "PS256", "EdDSA"]}}'::jsonb;

-- Replace EdDSA back to Ed25519 in existing JWT proof algorithm lists
UPDATE certify.credential_config
SET proof_types_supported = jsonb_set(
        proof_types_supported,
        '{jwt,proof_signing_alg_values_supported}',
        (
            SELECT COALESCE(jsonb_agg(DISTINCT val), '[]'::jsonb)
            FROM (
                     SELECT
                         CASE
                             WHEN alg = '"EdDSA"'::jsonb THEN '"Ed25519"'::jsonb
                             ELSE alg
                             END AS val
                     FROM jsonb_array_elements(proof_types_supported #> '{jwt,proof_signing_alg_values_supported}') AS alg
                 ) sub
        )
                            )
WHERE proof_types_supported #> '{jwt,proof_signing_alg_values_supported}' IS NOT NULL
  AND EXISTS (
      SELECT 1
      FROM jsonb_array_elements(proof_types_supported #> '{jwt,proof_signing_alg_values_supported}') AS alg
      WHERE alg = '"EdDSA"'::jsonb
  );

-- Restore NOT NULL on the holder binding columns
ALTER TABLE certify.credential_config
    ALTER COLUMN cryptographic_binding_methods_supported SET NOT NULL;

ALTER TABLE certify.credential_config
    ALTER COLUMN proof_types_supported SET NOT NULL;
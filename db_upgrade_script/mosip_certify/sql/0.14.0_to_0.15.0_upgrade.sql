UPDATE certify.credential_config
SET display = COALESCE((
    SELECT jsonb_agg(
                   CASE
                       WHEN elem->'logo' IS NOT NULL
                           AND (elem->'logo')::jsonb ? 'url' THEN
                           jsonb_set(
                                   elem::jsonb,
                                   '{logo}',
                                   ((elem->'logo')::jsonb - 'url')
                    || jsonb_build_object('uri', (elem->'logo')::jsonb -> 'url')
                )
                       ELSE elem::jsonb
                       END
           )
    FROM jsonb_array_elements(display::jsonb) AS elem
), '[]'::jsonb)
WHERE display IS NOT NULL;

ALTER TABLE certify.status_list_credential
ALTER COLUMN credential_status TYPE VARCHAR
        USING credential_status::text;
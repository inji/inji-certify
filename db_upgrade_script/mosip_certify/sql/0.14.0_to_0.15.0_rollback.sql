UPDATE certify.credential_config
SET display = (
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
)
WHERE display IS NOT NULL;
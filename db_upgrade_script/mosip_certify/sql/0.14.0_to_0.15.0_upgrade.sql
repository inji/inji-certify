UPDATE certify.credential_config
SET display = (
    SELECT jsonb_agg(
                   CASE
                       WHEN elem->'logo' ? 'url' THEN
                           jsonb_set(
                                   elem,
                                   '{logo}',
                                   (elem->'logo' - 'url') || jsonb_build_object('uri', elem->'logo'->'url')
                           )
                       ELSE elem
                       END
           )
    FROM jsonb_array_elements(COALESCE(display, '[]'::jsonb)) elem
)
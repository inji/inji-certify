UPDATE certify.credential_config
SET display = (
    SELECT jsonb_agg(
                   CASE
                       WHEN elem->'logo' ? 'uri' THEN
                           jsonb_set(
                                   elem,
                                   '{logo}',
                                   (elem->'logo' - 'uri') || jsonb_build_object('url', elem->'logo'->'uri')
                           )
                       ELSE elem
                       END
           )
    FROM jsonb_array_elements(COALESCE(display, '[]'::jsonb)) elem
)
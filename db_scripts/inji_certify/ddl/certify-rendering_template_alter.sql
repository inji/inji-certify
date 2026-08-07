-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : rendering_template
-- Purpose    : Alter rendering_template to support multiple SVG templates per credential type
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

ALTER TABLE rendering_template
    ADD COLUMN IF NOT EXISTS language VARCHAR(10) DEFAULT 'en',
    ADD COLUMN IF NOT EXISTS side VARCHAR(10) DEFAULT 'front',
    ADD COLUMN IF NOT EXISTS credential_config_key_id VARCHAR(2048);

COMMENT ON COLUMN rendering_template.language IS 'Language code for the SVG template (e.g. en, fr, ar).';
COMMENT ON COLUMN rendering_template.side IS 'Side of the credential the SVG represents: front or back.';
COMMENT ON COLUMN rendering_template.credential_config_key_id IS 'References credential_config.credential_config_key_id to link SVG templates to a credential type.';

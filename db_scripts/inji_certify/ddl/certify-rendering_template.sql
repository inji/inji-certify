-- Copyright 2024 Modular Open Source Identity Platform
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : rendering_template
-- Purpose    : Svg Template table
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

CREATE TABLE rendering_template (
    id VARCHAR(128) NOT NULL,
    template VARCHAR NOT NULL,
    cr_dtimes timestamp NOT NULL,
    upd_dtimes timestamp,
    CONSTRAINT pk_rendertmp_id PRIMARY KEY (id)
);

COMMENT ON TABLE rendering_template IS 'SVG Render Template: Contains svg render image for VC.';

COMMENT ON COLUMN rendering_template.id IS 'Template Id: Unique id assigned to save and identify template.';
COMMENT ON COLUMN rendering_template.template IS 'SVG Template Content: SVG Render Image for the VC details.';
COMMENT ON COLUMN rendering_template.cr_dtimes IS 'Date when the template was inserted in table.';
COMMENT ON COLUMN rendering_template.upd_dtimes IS 'Date when the template was last updated in table.';

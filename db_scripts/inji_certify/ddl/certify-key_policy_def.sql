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
-- Table Name : key_policy_def
-- Purpose    : Key Policy definition table
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
CREATE TABLE key_policy_def(
    app_id character varying(36) NOT NULL,
    key_validity_duration smallint,
    is_active boolean NOT NULL,
    pre_expire_days smallint,
    access_allowed character varying(1024),
    cr_by character varying(256) NOT NULL,
    cr_dtimes timestamp NOT NULL,
    upd_by character varying(256),
    upd_dtimes timestamp,
    is_deleted boolean DEFAULT FALSE,
    del_dtimes timestamp,
    CONSTRAINT pk_keypdef_id PRIMARY KEY (app_id)
);
COMMENT ON TABLE key_policy_def IS 'Key Policy Defination: Policy related to encryption key management is defined here. For eg. Expiry duration of a key generated.';
COMMENT ON COLUMN key_policy_def.app_id IS 'Application ID: Application id for which the key policy is defined';
COMMENT ON COLUMN key_policy_def.key_validity_duration IS 'Key Validity Duration: Duration for which key is valid';
COMMENT ON COLUMN key_policy_def.is_active IS 'IS_Active : Flag to mark whether the record is Active or In-active';
COMMENT ON COLUMN key_policy_def.cr_by IS 'Created By : ID or name of the user who create / insert record';
COMMENT ON COLUMN key_policy_def.cr_dtimes IS 'Created DateTimestamp : Date and Timestamp when the record is created/inserted';
COMMENT ON COLUMN key_policy_def.upd_by IS 'Updated By : ID or name of the user who update the record with new values';
COMMENT ON COLUMN key_policy_def.upd_dtimes IS 'Updated DateTimestamp : Date and Timestamp when any of the fields in the record is updated with new values.';
COMMENT ON COLUMN key_policy_def.is_deleted IS 'IS_Deleted : Flag to mark whether the record is Soft deleted.';
COMMENT ON COLUMN key_policy_def.del_dtimes IS 'Deleted DateTimestamp : Date and Timestamp when the record is soft deleted with is_deleted=TRUE';
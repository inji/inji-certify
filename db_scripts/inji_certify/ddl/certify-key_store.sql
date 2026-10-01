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
-- Table Name : key_store
-- Purpose    : Key Store table
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
CREATE TABLE key_store(
	id character varying(36) NOT NULL,
	master_key character varying(36) NOT NULL,
	private_key character varying(2500) NOT NULL,
	certificate_data character varying NOT NULL,
	cr_by character varying(256) NOT NULL,
	cr_dtimes timestamp NOT NULL,
	upd_by character varying(256),
	upd_dtimes timestamp,
	is_deleted boolean DEFAULT FALSE,
	del_dtimes timestamp,
	CONSTRAINT pk_keystr_id PRIMARY KEY (id)
);

COMMENT ON TABLE key_store IS 'Stores Encryption (Base) private keys along with certificates';
COMMENT ON COLUMN key_store.id IS 'Unique identifier (UUID) for referencing keys';
COMMENT ON COLUMN key_store.master_key IS 'UUID of the master key used to encrypt this key';
COMMENT ON COLUMN key_store.private_key IS 'Encrypted private key';
COMMENT ON COLUMN key_store.certificate_data IS 'X.509 encoded certificate data';
COMMENT ON COLUMN key_store.cr_by IS 'ID or name of the user who create / insert record';
COMMENT ON COLUMN key_store.cr_dtimes IS 'Date and Timestamp when the record is created/inserted';
COMMENT ON COLUMN key_store.upd_by IS 'ID or name of the user who update the record with new values';
COMMENT ON COLUMN key_store.upd_dtimes IS 'Date and Timestamp when any of the fields in the record is updated with new values.';
COMMENT ON COLUMN key_store.is_deleted IS 'Flag to mark whether the record is Soft deleted.';
COMMENT ON COLUMN key_store.del_dtimes IS 'Date and Timestamp when the record is soft deleted with is_deleted=TRUE';
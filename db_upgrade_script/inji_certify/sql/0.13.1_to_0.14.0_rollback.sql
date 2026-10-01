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
-- Table Name : credential_config, credential_template
-- Purpose    : To remove Certify v0.13.0 changes and make DB ready for Certify v0.12.1
--
-- Create By   	: Piyush Shukla
-- Created Date	: September 2025
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

-- Remove qr_settings and qr_signature_algo columns from credential_config
ALTER TABLE certify.credential_config
    DROP COLUMN IF EXISTS qr_settings,
    DROP COLUMN IF EXISTS qr_signature_algo;

-- IAR Session Table Rollback Script
-- This script removes the iar_session table and all associated objects

-- Drop indexes first
DROP INDEX IF EXISTS certify.idx_iar_session_authorization_code_used;
DROP INDEX IF EXISTS certify.idx_iar_session_expires_at;
DROP INDEX IF EXISTS certify.idx_iar_session_request_id;
DROP INDEX IF EXISTS certify.idx_iar_session_authorization_code;
DROP INDEX IF EXISTS certify.idx_iar_session_auth_session;
DROP INDEX IF EXISTS certify.idx_iar_session_scope;
DROP INDEX IF EXISTS certify.idx_iar_session_transaction_id;

-- Drop the table
DROP TABLE IF EXISTS certify.iar_session;


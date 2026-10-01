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
-- Table Name :shedlock, credential_status_transaction
-- Purpose    : To remove Certify v0.12.2 changes and make DB ready for Certify v0.12.1
--
-- Create By   	: Piyush Shukla
-- Created Date	: October 2025
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

-- Step 1: Drop shedlock table
DROP TABLE IF EXISTS certify.shedlock;

------------------------------ ************************************************** ------------------------------
-- Note: From version 0.13.0 onwards, the `credential_status_transaction` table is decoupled from the `ledger` table.
-- As a result, some rows may have missing `credential_id` values. Therefore, the foreign key constraint to the `ledger` table is not re-added to ensure smooth migration.
-- The foreign key constraint to the `status_list_credential` table is also excluded, as no operations in the `credential_status_transaction` table require updates to the `status_list_credential` table.
------------------------------ ************************************************** ------------------------------

-- Recreate foreign key to ledger table
--ALTER TABLE certify.credential_status_transaction
--    ADD CONSTRAINT fk_credential_status_transaction_ledger
--    FOREIGN KEY (credential_id)
--    REFERENCES certify.ledger(credential_id)
--    ON DELETE CASCADE
--    ON UPDATE CASCADE;

-- Recreate foreign key to status_list_credential table
--ALTER TABLE certify.credential_status_transaction
--    ADD CONSTRAINT fk_credential_status_transaction_status_list
--    FOREIGN KEY (status_list_credential_id)
--    REFERENCES certify.status_list_credential(id)
--    ON DELETE SET NULL
--    ON UPDATE CASCADE;
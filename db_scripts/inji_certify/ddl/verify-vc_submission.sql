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
--
-- Table required by the embedded inji-verify library.
-- Stores individual VC results extracted during VP verification.

CREATE TABLE IF NOT EXISTS vc_submission (
    transaction_id character varying(40) NOT NULL,
    vc             text NOT NULL
);

COMMENT ON TABLE vc_submission IS 'Stores individual VC results from VP verification by the embedded inji-verify library';
COMMENT ON COLUMN vc_submission.transaction_id IS 'Transaction ID linking the VC result to the issuance session';
COMMENT ON COLUMN vc_submission.vc IS 'Base64-encoded or JSON VC extracted from the verified VP token';

CREATE INDEX IF NOT EXISTS idx_vc_submission_transaction_id ON vc_submission (transaction_id);

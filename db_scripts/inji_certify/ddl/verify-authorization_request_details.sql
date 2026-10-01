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
-- Stores VP authorization requests created during the presentation-during-issuance flow.

CREATE TABLE IF NOT EXISTS authorization_request_details (
    request_id      character varying(40) NOT NULL,
    transaction_id  character varying(40) NOT NULL,
    authorization_details text NOT NULL,
    expires_at      bigint NOT NULL,
    CONSTRAINT pk_authorization_request_details PRIMARY KEY (request_id)
);

COMMENT ON TABLE authorization_request_details IS 'Stores VP authorization request details created by the embedded inji-verify library';
COMMENT ON COLUMN authorization_request_details.request_id IS 'Unique request ID for the VP authorization request';
COMMENT ON COLUMN authorization_request_details.transaction_id IS 'Transaction ID linking this request to the issuance session';
COMMENT ON COLUMN authorization_request_details.authorization_details IS 'JSON blob containing full OpenID4VP authorization request details';
COMMENT ON COLUMN authorization_request_details.expires_at IS 'Epoch-millis expiry of the authorization request';

CREATE INDEX IF NOT EXISTS idx_ard_transaction_id ON authorization_request_details (transaction_id);

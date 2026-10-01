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
-- Table Name : shedlock
-- Purpose    : Table for managing distributed locks using ShedLock library
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
-- Create shedlock table for distributed locking
CREATE TABLE IF NOT EXISTS shedlock (
  name VARCHAR(64),
  lock_until TIMESTAMPTZ(3) NOT NULL,
  locked_at TIMESTAMPTZ(3) NOT NULL,
  locked_by VARCHAR(255) NOT NULL,
  PRIMARY KEY (name)
);

COMMENT ON TABLE shedlock IS 'Table for managing distributed locks using ShedLock library.';
COMMENT ON COLUMN shedlock.name IS 'Unique name of the lock.';
COMMENT ON COLUMN shedlock.lock_until IS 'Timestamp until which the lock is held. NULL if not locked.';
COMMENT ON COLUMN shedlock.locked_at IS 'Timestamp when the lock was acquired. NULL if not locked.';
COMMENT ON COLUMN shedlock.locked_by IS 'Identifier of the node/process that holds the lock. NULL if not locked.';
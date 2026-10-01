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

\c :mosipdbname

GRANT CONNECT
   ON DATABASE :mosipdbname
   TO :dbuname;

GRANT USAGE
   ON SCHEMA certify
   TO :dbuname;

GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES
   ON ALL TABLES IN SCHEMA certify
   TO :dbuname;

ALTER DEFAULT PRIVILEGES IN SCHEMA certify
	GRANT SELECT,INSERT,UPDATE,DELETE,REFERENCES ON TABLES TO :dbuname;

GRANT USAGE, SELECT
   ON ALL SEQUENCES IN SCHEMA certify
   TO :dbuname;

ALTER DEFAULT PRIVILEGES IN SCHEMA certify
   GRANT USAGE, SELECT ON SEQUENCES TO :dbuname;


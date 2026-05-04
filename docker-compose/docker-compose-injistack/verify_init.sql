CREATE DATABASE inji_verify
  ENCODING = 'UTF8'
  LC_COLLATE = 'en_US.UTF-8'
  LC_CTYPE = 'en_US.UTF-8'
  TABLESPACE = pg_default
  OWNER = postgres
  TEMPLATE  = template0;

COMMENT ON DATABASE inji_verify IS 'verify related data is stored in this database';

\c inji_verify postgres

DROP SCHEMA IF EXISTS verify CASCADE;
CREATE SCHEMA verify;
ALTER SCHEMA verify OWNER TO postgres;
ALTER DATABASE inji_verify SET search_path TO verify,pg_catalog,public;

CREATE TABLE verify.authorization_request_details (
                                                                    request_id character varying(40) NOT NULL,
    transaction_id character varying(40) NOT NULL,
    authorization_details text NOT NULL,
    expires_at bigint NOT NULL
    );

CREATE TABLE verify.presentation_definition(
                                                             id character varying(36) NOT NULL,
    input_descriptors jsonb NOT NULL,
    name character varying(500),
    purpose character varying(500),
    vp_format text,
    submission_requirements text
    );

CREATE TABLE verify.vc_submission(
                                                   transaction_id character varying(40) NOT NULL,
    vc text NOT NULL
    );

CREATE TABLE verify.vp_submission(
                                                   request_id character varying(40) NOT NULL,
    vp_token VARCHAR NOT NULL,
    presentation_submission text NOT NULL,
    error character varying(100) NULL,
    error_description character varying(200) NULL
    );
-- Seed fixtures for the postgres provider integration test.
-- Run against a fresh server as a superuser.

CREATE ROLE app_group NOLOGIN;
CREATE ROLE app_admin WITH LOGIN PASSWORD 'Str0ng!Passw0rd2026' CREATEROLE CONNECTION LIMIT 5 VALID UNTIL '2030-01-01T00:00:00Z';
GRANT app_group TO app_admin;

CREATE DATABASE appdb OWNER app_admin;

\connect appdb

CREATE SCHEMA appschema AUTHORIZATION app_admin;

-- CIS hardening: revoke CREATE on the public schema from PUBLIC
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS postgres_fdw;

-- a SECURITY DEFINER function (privilege-escalation surface) with an EXECUTE grant
CREATE FUNCTION appschema.secdef_fn() RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1';
GRANT EXECUTE ON FUNCTION appschema.secdef_fn() TO app_group;

-- a table with a DML grant (CIS 4.6) and a row-level security policy (CIS 4.7)
CREATE TABLE appschema.t1 (id integer, secret text);
GRANT SELECT ON appschema.t1 TO app_group;
ALTER TABLE appschema.t1 ENABLE ROW LEVEL SECURITY;
CREATE POLICY t1_sel ON appschema.t1 FOR SELECT TO app_group USING (true);

-- foreign server + user mapping carrying a (redacted) password option
CREATE SERVER remote_srv FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host 'remote.example', dbname 'remote', port '5432');
CREATE USER MAPPING FOR app_admin SERVER remote_srv
  OPTIONS (user 'remoteuser', password 'notreal');

-- a logical-replication publication
CREATE PUBLICATION apppub FOR ALL TABLES;

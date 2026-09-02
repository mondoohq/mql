-- Copyright Mondoo, Inc. 2024, 2026
-- SPDX-License-Identifier: BUSL-1.1
--
-- Seeds security-relevant fixtures the integration test asserts on. Run against
-- a server with SQL-driven access management enabled, as an account that can
-- manage access (for example the default user), for example:
--
--   clickhouse-client --multiquery < seed.sql
--
-- No credentials are set here on purpose (nothing to leak); the fixtures the
-- test needs are a password-less account, a host restriction, and a broad grant.

-- A password-less user: can log in without a credential (a finding).
CREATE USER IF NOT EXISTS weakuser IDENTIFIED WITH no_password;

-- A role granted broad SELECT on everything, and a user that holds it. The user
-- is restricted to a host range so the test can assert it is not any-host.
CREATE ROLE IF NOT EXISTS analyst;
GRANT SELECT ON *.* TO analyst;
CREATE USER IF NOT EXISTS appuser IDENTIFIED WITH no_password HOST IP '10.0.0.0/8';
GRANT analyst TO appuser;

-- A user pinned to one IP address that also carries a host name regular
-- expression matching every name. ClickHouse admits a connection when any of
-- host_ip, host_names_regexp or host_names_like matches, so this account is
-- reachable from anywhere despite the narrow IP entry.
--
-- The expression is spelled "^.*$" rather than ".*" on purpose: ClickHouse
-- rewrites a bare ".*" into the any-host form and moves it into host_ip, which
-- would hide the case this fixture exists to cover.
CREATE USER IF NOT EXISTS openregexpuser IDENTIFIED WITH no_password HOST IP '10.0.0.1', REGEXP '^.*$';

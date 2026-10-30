#!/usr/bin/env bash
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1

# Prints SQL that seeds a secure single-node cluster with the objects the
# integration tests read: roles of both password formats, a nested admin, role
# defaults, a database with grants, host-based authentication rules, and two
# backup schedules, one encrypted. Passwords and the passphrase are random:
# the tests read how a password is stored, never the password.
#
#   testdata/seed.sh | docker exec -i crdb ./cockroach sql --certs-dir=/certs --host=127.0.0.1
set -euo pipefail

random() { head -c 18 /dev/urandom | base64 | tr -d '/+='; }
app=$(random)
legacy=$(random)
backup=$(random)

cat <<SQL
CREATE USER IF NOT EXISTS app WITH PASSWORD '${app}' VALID UNTIL '2030-01-01';
SET CLUSTER SETTING server.user_login.password_encryption TO 'crdb-bcrypt';
CREATE USER IF NOT EXISTS legacy WITH PASSWORD '${legacy}';
RESET CLUSTER SETTING server.user_login.password_encryption;
CREATE ROLE IF NOT EXISTS ops WITH NOLOGIN CREATEDB;
GRANT admin TO ops;
CREATE ROLE IF NOT EXISTS nested;
GRANT ops TO nested;
ALTER ROLE app SET idle_in_session_timeout = '15m';
ALTER ROLE ALL SET statement_timeout = '1h';

CREATE DATABASE IF NOT EXISTS shop;
CREATE TABLE IF NOT EXISTS shop.orders (id INT PRIMARY KEY);
GRANT CONNECT ON DATABASE shop TO app;
GRANT SELECT ON shop.orders TO app;

SET CLUSTER SETTING server.host_based_authentication.configuration = e'host all root all cert\nhostssl all app 10.0.0.0/8 cert-scram-sha-256\nhost all all 0.0.0.0/0 cert-password\nlocal all all password';

CREATE SCHEDULE IF NOT EXISTS enc FOR BACKUP INTO 'nodelocal://1/enc' WITH encryption_passphrase = '${backup}' RECURRING '@daily' FULL BACKUP ALWAYS;
CREATE SCHEDULE IF NOT EXISTS plain FOR BACKUP INTO 'nodelocal://1/plain' RECURRING '@daily' FULL BACKUP ALWAYS;
SQL

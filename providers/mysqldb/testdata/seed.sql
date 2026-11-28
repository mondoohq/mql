-- Seed fixtures for the mysqldb provider integration test.
-- Works on both MySQL 8 and MariaDB. Run as a privileged user (root).

CREATE DATABASE IF NOT EXISTS appdb;

CREATE USER 'appuser'@'%' IDENTIFIED BY 'Str0ng!Passw0rd2026';
GRANT SELECT, INSERT ON appdb.* TO 'appuser'@'%';
GRANT PROCESS ON *.* TO 'appuser'@'%';

-- a SECURITY DEFINER routine (privilege-escalation surface). Single-statement
-- body needs no DELIMITER change.
CREATE DEFINER='appuser'@'%' PROCEDURE appdb.secdef_proc() SQL SECURITY DEFINER SELECT 1;

-- column metadata: unsigned integers (MariaDB adds display widths), a column
-- comment, both nullability states, and a view over the table
CREATE TABLE appdb.customers (id bigint unsigned NOT NULL PRIMARY KEY,
  email varchar(255) NOT NULL COMMENT 'login address', ssn char(11) NULL,
  balance decimal(10,2), flags int unsigned, created_at datetime(3));
CREATE VIEW appdb.customer_emails AS SELECT id, email FROM appdb.customers;

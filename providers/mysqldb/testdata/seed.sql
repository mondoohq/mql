-- Seed fixtures for the mysqldb provider integration test.
-- Works on both MySQL 8 and MariaDB. Run as a privileged user (root).

CREATE DATABASE IF NOT EXISTS appdb;

CREATE USER 'appuser'@'%' IDENTIFIED BY 'Str0ng!Passw0rd2026';
GRANT SELECT, INSERT ON appdb.* TO 'appuser'@'%';
GRANT PROCESS ON *.* TO 'appuser'@'%';

-- a SECURITY DEFINER routine (privilege-escalation surface). Single-statement
-- body needs no DELIMITER change.
CREATE DEFINER='appuser'@'%' PROCEDURE appdb.secdef_proc() SQL SECURITY DEFINER SELECT 1;

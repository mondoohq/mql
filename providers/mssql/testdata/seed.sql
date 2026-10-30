SET NOCOUNT ON;
GO
CREATE DATABASE TESTDB;
GO
-- server login with password policy (CIS 4.2/4.3)
CREATE LOGIN testlogin WITH PASSWORD = 'Str0ng!Passw0rd2026', CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
GO
-- server-level permission grant (mssql.permission at server scope)
GRANT VIEW ANY DEFINITION TO testlogin;
GRANT CONNECT SQL TO testlogin;
GO
-- user-defined server role with a member (serverRole.members / memberOfRoles)
CREATE SERVER ROLE testsrvrole;
ALTER SERVER ROLE testsrvrole ADD MEMBER testlogin;
GO
-- server credential mapped to a login (credential.mappedLogins)
CREATE CREDENTIAL testcred WITH IDENTITY = 'CONTOSO\svcacct', SECRET = 'notreal';
GO
ALTER LOGIN testlogin WITH CREDENTIAL = testcred;
GO
-- linked server metadata (mssql.linkedServer + linkedLogins)
EXEC sp_addlinkedserver @server = 'LINKSRV', @srvproduct = '', @provider = 'SQLNCLI', @datasrc = 'remote.contoso.com';
GO
-- server audit + specification capturing login groups (CIS 5.4)
CREATE SERVER AUDIT TestAudit TO FILE (FILEPATH = '/var/opt/mssql/data/');
GO
CREATE SERVER AUDIT SPECIFICATION TestAuditSpec FOR SERVER AUDIT TestAudit
  ADD (FAILED_LOGIN_GROUP), ADD (SUCCESSFUL_LOGIN_GROUP) WITH (STATE = ON);
GO
-- database principals, roles, permissions, keys, app role
USE TESTDB;
GO
CREATE USER testuser FOR LOGIN testlogin;
CREATE ROLE testrole;
ALTER ROLE testrole ADD MEMBER testuser;
GRANT SELECT TO testuser;
GRANT CONNECT TO guest;  -- CIS 3.2 negative case
GO
CREATE APPLICATION ROLE testapprole WITH PASSWORD = 'Str0ng!Passw0rd2026', DEFAULT_SCHEMA = dbo;
GO
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'Str0ng!Passw0rd2026';
CREATE SYMMETRIC KEY TestSymKey WITH ALGORITHM = AES_256 ENCRYPTION BY PASSWORD = 'Str0ng!Passw0rd2026';
CREATE ASYMMETRIC KEY TestAsymKey WITH ALGORITHM = RSA_2048;
GO
-- database-scoped credential (mssql.databaseScopedCredential)
CREATE DATABASE SCOPED CREDENTIAL testdbcred WITH IDENTITY = 'scopedidentity', SECRET = 'notreal';
GO
-- encrypted backup (CIS 7.3)
USE master;
GO
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'Str0ng!Passw0rd2026';
CREATE CERTIFICATE TestBackupCert WITH SUBJECT = 'mssql provider test backup cert';
GO
BACKUP DATABASE TESTDB TO DISK = '/var/opt/mssql/data/TESTDB_enc.bak'
  WITH ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = TestBackupCert), INIT;
GO
BACKUP DATABASE master TO DISK = '/var/opt/mssql/data/master_plain.bak' WITH INIT;
GO
PRINT 'seed2 complete';
GO

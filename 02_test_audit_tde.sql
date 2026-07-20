/* ==========================================================================
   02_test_audit_tde.sql

   Exercises 01_enable_audit_login_tde.sql:
     - Creates a dummy database (AuditTestDB)
     - Creates master key + certificate, enables TDE on it
     - Simulates certificate "renewal" (new cert, re-key DEK, alter, drop old)
     - Creates/drops a throwaway login to generate login/logoff events
     - Reads back the audit file and shows what was captured

   Run 01_enable_audit_login_tde.sql first. Requires sysadmin.
   TDE requires SQL Server Standard (2019+) or Enterprise edition.
   ========================================================================== */

:setvar AuditPath "D:\SQLAudit\"
:setvar CertBackupPath "D:\SQLAudit\Certs\"

USE master;
GO

-- ============================================================
-- 1. Dummy test database
-- ============================================================
IF DB_ID(N'AuditTestDB') IS NOT NULL
BEGIN
    ALTER DATABASE [AuditTestDB] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE [AuditTestDB];
END
GO

CREATE DATABASE [AuditTestDB];
GO

-- ============================================================
-- 2. Master key (protects the certificate) - CHANGE THE PASSWORD
-- ============================================================
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = N'##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = N'Ch@ngeThisStrongP@ssw0rd!';
GO

-- ============================================================
-- 3. Certificate to protect the Database Encryption Key
-- ============================================================
IF EXISTS (SELECT 1 FROM sys.certificates WHERE name = N'AuditTestDB_TDE_Cert')
    DROP CERTIFICATE [AuditTestDB_TDE_Cert];
GO

CREATE CERTIFICATE [AuditTestDB_TDE_Cert]
    WITH SUBJECT = N'TDE Certificate for AuditTestDB';
GO

-- Always back up cert + private key in real environments
BACKUP CERTIFICATE [AuditTestDB_TDE_Cert]
TO FILE = N'$(CertBackupPath)AuditTestDB_TDE_Cert.cer'
WITH PRIVATE KEY
(
    FILE = N'$(CertBackupPath)AuditTestDB_TDE_Cert.pvk',
    ENCRYPTION BY PASSWORD = N'Ch@ngeThisStrongP@ssw0rd!'
);
GO

-- ============================================================
-- 4. Create the Database Encryption Key and turn TDE on
-- ============================================================
USE [AuditTestDB];
GO

CREATE DATABASE ENCRYPTION KEY
    WITH ALGORITHM = AES_256
    ENCRYPTION BY SERVER CERTIFICATE [AuditTestDB_TDE_Cert];
GO

ALTER DATABASE [AuditTestDB] SET ENCRYPTION ON;
GO

WAITFOR DELAY '00:00:05';
GO

SELECT DB_NAME(k.database_id) AS db_name,
       k.encryption_state,
       CASE k.encryption_state
            WHEN 0 THEN 'No database encryption key present'
            WHEN 1 THEN 'Unencrypted'
            WHEN 2 THEN 'Encryption in progress'
            WHEN 3 THEN 'Encrypted'
            WHEN 4 THEN 'Key change in progress'
            WHEN 5 THEN 'Decryption in progress'
            WHEN 6 THEN 'Protection change in progress'
       END AS encryption_state_desc,
       k.percent_complete
FROM sys.dm_database_encryption_keys k
WHERE k.database_id = DB_ID(N'AuditTestDB');
GO

USE master;
GO

-- ============================================================
-- 5. Simulate certificate "renewal": create new cert, back it up,
--    re-key the DEK onto it, alter it, then drop the old cert.
-- ============================================================
IF EXISTS (SELECT 1 FROM sys.certificates WHERE name = N'AuditTestDB_TDE_Cert_New')
    DROP CERTIFICATE [AuditTestDB_TDE_Cert_New];
GO

CREATE CERTIFICATE [AuditTestDB_TDE_Cert_New]
    WITH SUBJECT = N'Renewed TDE Certificate for AuditTestDB';
GO

BACKUP CERTIFICATE [AuditTestDB_TDE_Cert_New]
TO FILE = N'$(CertBackupPath)AuditTestDB_TDE_Cert_New.cer'
WITH PRIVATE KEY
(
    FILE = N'$(CertBackupPath)AuditTestDB_TDE_Cert_New.pvk',
    ENCRYPTION BY PASSWORD = N'Ch@ngeThisStrongP@ssw0rd!'
);
GO

USE [AuditTestDB];
GO

-- Re-key the DEK onto the new certificate (this is the real "renewal" step)
ALTER DATABASE ENCRYPTION KEY
    ENCRYPTION BY SERVER CERTIFICATE [AuditTestDB_TDE_Cert_New];
GO

USE master;
GO

-- ALTER CERTIFICATE event (rotate the private-key protection password)
ALTER CERTIFICATE [AuditTestDB_TDE_Cert_New]
    WITH PRIVATE KEY (ENCRYPTION BY PASSWORD = N'AnotherStrongP@ssw0rd!');
GO

-- DROP CERTIFICATE event (retire the now-unused old certificate)
DROP CERTIFICATE [AuditTestDB_TDE_Cert];
GO

-- ============================================================
-- 6. Login / logoff events
-- ============================================================
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'AuditTestLogin')
    DROP LOGIN [AuditTestLogin];
GO

CREATE LOGIN [AuditTestLogin] WITH PASSWORD = N'T3stL0gin!Pwd', CHECK_POLICY = ON;
GO

PRINT 'Now, from a separate session (e.g. sqlcmd), connect and disconnect with';
PRINT 'AuditTestLogin to generate SUCCESSFUL_LOGIN_GROUP / LOGOUT_GROUP events,';
PRINT 'and try one wrong password to generate a FAILED_LOGIN_GROUP event, e.g.:';
PRINT '  sqlcmd -S <server> -U AuditTestLogin -P T3stL0gin!Pwd -Q "SELECT 1"';
PRINT '  sqlcmd -S <server> -U AuditTestLogin -P WrongPassword -Q "SELECT 1"';
GO

WAITFOR DELAY '00:00:05';
GO

-- ============================================================
-- 7. Read back the audit and show what was captured
-- ============================================================
SELECT af.event_time,
       aa.name AS action_name,
       af.succeeded,
       af.server_principal_name,
       af.database_name,
       af.object_name,
       af.statement
FROM sys.fn_get_audit_file (N'$(AuditPath)Audit_Login_TDE*.sqlaudit', DEFAULT, DEFAULT) af
LEFT JOIN sys.dm_audit_actions aa ON af.action_id = aa.action_id
ORDER BY af.event_time DESC;
GO

-- ============================================================
-- 8. Cleanup (run manually once you're satisfied)
-- ============================================================
/*
USE master;
GO
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'AuditTestLogin')
    DROP LOGIN [AuditTestLogin];

IF DB_ID(N'AuditTestDB') IS NOT NULL
BEGIN
    ALTER DATABASE [AuditTestDB] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE [AuditTestDB];
END

IF EXISTS (SELECT 1 FROM sys.certificates WHERE name = N'AuditTestDB_TDE_Cert_New')
    DROP CERTIFICATE [AuditTestDB_TDE_Cert_New];

-- Only drop the audit itself if you no longer want it monitoring the instance:
-- ALTER SERVER AUDIT SPECIFICATION [AuditSpec_Login_TDE] WITH (STATE = OFF);
-- DROP SERVER AUDIT SPECIFICATION [AuditSpec_Login_TDE];
-- ALTER SERVER AUDIT [Audit_Login_TDE] WITH (STATE = OFF);
-- DROP SERVER AUDIT [Audit_Login_TDE];
*/

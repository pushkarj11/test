/* ==========================================================================
   01_enable_audit_login_tde.sql

   Creates a SQL Server Audit that captures:
     - Login / logout events (success + failure, password changes,
       server principal create/alter/drop)
     - TDE / certificate / key lifecycle events (CREATE/ALTER/DROP
       CERTIFICATE, MASTER KEY, DATABASE ENCRYPTION KEY, ALTER DATABASE
       SET ENCRYPTION ON/OFF, BACKUP CERTIFICATE / BACKUP DATABASE)

   Requirements:
     - Run as sysadmin (ALTER ANY SERVER AUDIT permission)
     - The SQL Server service account needs write access to @AuditPath
     - Edit @AuditPath / file sizing below before running
   ========================================================================== */

USE master;
GO

-- ---------------------------------------------------------------------
-- EDIT ME: folder must exist and be writable by the SQL Server service
-- account. Use a local/secured path, not a share everyone can browse.
-- ---------------------------------------------------------------------
:setvar AuditPath "D:\SQLAudit\"

-- ============================================================
-- 1. Server Audit object (writes to file; rotate at 256MB x 50)
-- ============================================================
IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N'Audit_Login_TDE')
BEGIN
    IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N'Audit_Login_TDE' AND is_state_enabled = 1)
        ALTER SERVER AUDIT [Audit_Login_TDE] WITH (STATE = OFF);
    DROP SERVER AUDIT [Audit_Login_TDE];
END
GO

CREATE SERVER AUDIT [Audit_Login_TDE]
TO FILE
(
    FILEPATH = N'$(AuditPath)',
    MAXSIZE = 256 MB,
    MAX_ROLLOVER_FILES = 50,
    RESERVE_DISK_SPACE = OFF
)
WITH
(
    QUEUE_DELAY = 1000,
    ON_FAILURE = CONTINUE,      -- use SHUTDOWN if audit gaps are unacceptable
    AUDIT_GUID = NEWID()
);
GO

ALTER SERVER AUDIT [Audit_Login_TDE] WITH (STATE = ON);
GO

-- ============================================================
-- 2. Server Audit Specification
--    NOTE: only ONE server audit specification can be bound to a
--    given server audit, so every action group goes in one CREATE.
-- ============================================================
IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = N'AuditSpec_Login_TDE')
BEGIN
    ALTER SERVER AUDIT SPECIFICATION [AuditSpec_Login_TDE] WITH (STATE = OFF);
    DROP SERVER AUDIT SPECIFICATION [AuditSpec_Login_TDE];
END
GO

CREATE SERVER AUDIT SPECIFICATION [AuditSpec_Login_TDE]
FOR SERVER AUDIT [Audit_Login_TDE]
    -- Login / logoff
    ADD (SUCCESSFUL_LOGIN_GROUP),
    ADD (FAILED_LOGIN_GROUP),
    ADD (LOGOUT_GROUP),
    ADD (LOGIN_CHANGE_PASSWORD_GROUP),
    ADD (SERVER_PRINCIPAL_CHANGE_GROUP),        -- CREATE/ALTER/DROP LOGIN
    -- TDE / certificate / key lifecycle
    ADD (DATABASE_CHANGE_GROUP),                -- CREATE/ALTER/DROP DATABASE, incl. SET ENCRYPTION ON/OFF
    ADD (DATABASE_OBJECT_CHANGE_GROUP),         -- CREATE/ALTER/DROP CERTIFICATE, MASTER KEY, DEK, SYM/ASYM KEY
    ADD (SERVER_OBJECT_CHANGE_GROUP),           -- server-scoped key/cert objects (endpoints, AG certs, etc.)
    ADD (BACKUP_RESTORE_GROUP)                  -- BACKUP CERTIFICATE, database backup/restore
WITH (STATE = ON);
GO

-- ============================================================
-- 3. Verify
-- ============================================================
SELECT name, is_state_enabled, audit_file_path
FROM sys.server_audits;

SELECT s.name AS spec_name, s.is_state_enabled, d.audit_action_name
FROM sys.server_audit_specifications s
JOIN sys.server_audit_specification_details d
    ON s.server_specification_id = d.server_specification_id
ORDER BY d.audit_action_name;
GO

CREATE SERVER AUDIT SPECIFICATION [ServerAuditSpec_Crypto_TDE]
FOR SERVER AUDIT [Audit_Crypto_TDE]
    ADD (DATABASE_OBJECT_CHANGE_GROUP)             -- certs, DMK, DEK, sym/asym keys, TDE toggle
,   ADD (DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP)   -- ALTER AUTHORIZATION on a cert/key
,   ADD (DATABASE_OBJECT_PERMISSION_CHANGE_GROUP)  -- GRANT/DENY/REVOKE on a cert/key
,   ADD (DATABASE_CHANGE_GROUP)                    -- CREATE/ALTER/DROP DATABASE
,   ADD (SERVER_OBJECT_CHANGE_GROUP)               -- server-scoped objects
WITH (STATE = ON);
GO

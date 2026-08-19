-- =========================================================================
-- MODULE 1B: IP WHITELIST + ACCOUNT LOCKOUT (additive patch)
-- =========================================================================
-- Apply this script after `database_schema.sql` to extend the `users` table
-- with the access-failed-count and lockout columns used by
-- `Middlewares/IpWhitelistMiddleware` and `AccountController.RecordFailedAttemptAsync`.
-- =========================================================================

SET NOCOUNT ON;
SET XACT_ABORT ON;
GO

IF NOT EXISTS (
    SELECT 1
    FROM sys.columns
    WHERE object_id = OBJECT_ID(N'dbo.users')
      AND name = N'access_failed_count'
)
BEGIN
    ALTER TABLE dbo.users
        ADD access_failed_count INT NOT NULL
            CONSTRAINT DF_users_access_failed_count DEFAULT (0);
END
GO

IF NOT EXISTS (
    SELECT 1
    FROM sys.columns
    WHERE object_id = OBJECT_ID(N'dbo.users')
      AND name = N'lockout_end_utc'
)
BEGIN
    ALTER TABLE dbo.users
        ADD lockout_end_utc DATETIME NULL;
END
GO

PRINT 'Module 1B patch applied: users.access_failed_count + users.lockout_end_utc';
GO

SET NOCOUNT ON;
SET XACT_ABORT ON;
SET ANSI_NULLS ON;
SET ANSI_PADDING ON;
SET ANSI_WARNINGS ON;
SET ARITHABORT ON;
SET CONCAT_NULL_YIELDS_NULL ON;
SET QUOTED_IDENTIFIER ON;
SET NUMERIC_ROUNDABORT OFF;

BEGIN TRY
    BEGIN TRANSACTION;

    IF OBJECT_ID(N'dbo.users', N'U') IS NULL
        THROW 50001, 'Không tìm thấy bảng dbo.users. Hãy chạy database_schema.sql cho database mới.', 1;

    IF OBJECT_ID(N'dbo.system_audit_logs', N'U') IS NULL
        THROW 50002, 'Không tìm thấy bảng dbo.system_audit_logs. Hãy chạy database_schema.sql cho database mới.', 1;

    UPDATE dbo.users
    SET status = 'locked'
    WHERE status IS NULL;

    IF EXISTS
    (
        SELECT 1
        FROM sys.columns
        WHERE object_id = OBJECT_ID(N'dbo.users')
          AND name = N'status'
          AND is_nullable = 1
    )
    BEGIN
        ALTER TABLE dbo.users
            ALTER COLUMN status VARCHAR(20) NOT NULL;
    END;

    IF COL_LENGTH(N'dbo.users', N'security_stamp') IS NULL
    BEGIN
        ALTER TABLE dbo.users
        ADD security_stamp UNIQUEIDENTIFIER NOT NULL
            CONSTRAINT DF_users_security_stamp DEFAULT (NEWID()) WITH VALUES;
    END;

    IF NOT EXISTS
    (
        SELECT 1
        FROM sys.indexes
        WHERE object_id = OBJECT_ID(N'dbo.users')
          AND name = N'idx_users_status_role'
    )
    BEGIN
        CREATE INDEX idx_users_status_role
            ON dbo.users(status, role)
            INCLUDE(username, email);
    END;

    IF NOT EXISTS
    (
        SELECT 1
        FROM sys.indexes
        WHERE object_id = OBJECT_ID(N'dbo.system_audit_logs')
          AND name = N'idx_audit_logs_login_history'
    )
    BEGIN
        CREATE INDEX idx_audit_logs_login_history
            ON dbo.system_audit_logs(user_id, created_at DESC)
            INCLUDE(action_type, ip_address, device_info)
            WHERE module = 'Tai_Khoan' AND user_id IS NOT NULL;
    END;

    IF OBJECT_ID(N'dbo.employees', N'U') IS NOT NULL
       AND NOT EXISTS
       (
           SELECT 1
           FROM dbo.employees
           WHERE user_id IS NULL
             AND status IN ('dang_lam_viec', 'thu_viec')
       )
       AND NOT EXISTS
       (
           SELECT 1
           FROM dbo.employees
           WHERE email = 'minhanh@hanamedia.com'
       )
       AND NOT EXISTS
       (
           SELECT 1
           FROM dbo.users
           WHERE email = 'minhanh@hanamedia.com'
       )
    BEGIN
        INSERT INTO dbo.employees
            (full_name, dob, phone, email, address, joined_date, department, position,
             contract_type, basic_salary, allowance, status)
        VALUES
            (N'Nguyễn Minh Anh', '1998-05-12', '0900000001', 'minhanh@hanamedia.com',
             N'Hà Nội', '2026-08-01', 'Y_tuong', N'Nhân viên Ý tưởng',
             'thu_viec', 12000000, 1000000, 'dang_lam_viec');
    END;

    COMMIT TRANSACTION;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0
        ROLLBACK TRANSACTION;

    THROW;
END CATCH;

using HanaMedia.Models;

namespace HanaMedia.Services.Security;

public enum PasswordVerificationStatus
{
    Failed,
    Success,
    SuccessRehashNeeded
}

public interface IAccountPasswordService
{
    string HashPassword(User user, string password);

    PasswordVerificationStatus VerifyPassword(User user, string password);

    string GenerateTemporaryPassword();
}

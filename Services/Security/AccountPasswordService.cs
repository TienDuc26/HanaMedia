using System.Security.Cryptography;
using System.Text;
using HanaMedia.Models;
using Microsoft.AspNetCore.Identity;

namespace HanaMedia.Services.Security;

public sealed class AccountPasswordService : IAccountPasswordService
{
    private const int TemporaryPasswordLength = 16;
    private const string LowercaseCharacters = "abcdefghijkmnopqrstuvwxyz";
    private const string UppercaseCharacters = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string DigitCharacters = "23456789";
    private const string SymbolCharacters = "!@$?_-";
    private const string AllCharacters =
        LowercaseCharacters + UppercaseCharacters + DigitCharacters + SymbolCharacters;

    private readonly IPasswordHasher<User> _passwordHasher;

    public AccountPasswordService(IPasswordHasher<User> passwordHasher)
    {
        _passwordHasher = passwordHasher ?? throw new ArgumentNullException(nameof(passwordHasher));
    }

    public string HashPassword(User user, string password)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(password);

        return _passwordHasher.HashPassword(user, password);
    }

    public PasswordVerificationStatus VerifyPassword(User user, string password)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(password);

        if (string.IsNullOrEmpty(user.PasswordHash))
        {
            return PasswordVerificationStatus.Failed;
        }

        if (IsLegacySha256Hash(user.PasswordHash))
        {
            return VerifyLegacySha256(user.PasswordHash, password)
                ? PasswordVerificationStatus.SuccessRehashNeeded
                : PasswordVerificationStatus.Failed;
        }

        try
        {
            var result = _passwordHasher.VerifyHashedPassword(
                user,
                user.PasswordHash,
                password);

            return result switch
            {
                PasswordVerificationResult.Success => PasswordVerificationStatus.Success,
                PasswordVerificationResult.SuccessRehashNeeded =>
                    PasswordVerificationStatus.SuccessRehashNeeded,
                _ => PasswordVerificationStatus.Failed
            };
        }
        catch (FormatException)
        {
            return PasswordVerificationStatus.Failed;
        }
        catch (CryptographicException)
        {
            return PasswordVerificationStatus.Failed;
        }
    }

    public string GenerateTemporaryPassword()
    {
        var password = new char[TemporaryPasswordLength];
        password[0] = GetRandomCharacter(LowercaseCharacters);
        password[1] = GetRandomCharacter(UppercaseCharacters);
        password[2] = GetRandomCharacter(DigitCharacters);
        password[3] = GetRandomCharacter(SymbolCharacters);

        for (var index = 4; index < password.Length; index++)
        {
            password[index] = GetRandomCharacter(AllCharacters);
        }

        for (var index = password.Length - 1; index > 0; index--)
        {
            var swapIndex = RandomNumberGenerator.GetInt32(index + 1);
            (password[index], password[swapIndex]) = (password[swapIndex], password[index]);
        }

        return new string(password);
    }

    private static bool IsLegacySha256Hash(string storedHash)
    {
        if (storedHash.Length != 64)
        {
            return false;
        }

        foreach (var character in storedHash)
        {
            if (character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool VerifyLegacySha256(string storedHash, string password)
    {
        var expectedHash = Convert.FromHexString(storedHash);
        var actualHash = SHA256.HashData(Encoding.UTF8.GetBytes(password));

        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
    }

    private static char GetRandomCharacter(string characters) =>
        characters[RandomNumberGenerator.GetInt32(characters.Length)];
}

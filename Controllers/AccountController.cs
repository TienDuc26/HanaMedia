using System.Globalization;
using System.Security.Claims;
using HanaMedia.Constants;
using HanaMedia.Models;
using HanaMedia.Services.Auditing;
using HanaMedia.Services.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HanaMedia.Controllers;

public sealed class AccountController : Controller
{
    private const string InvalidCredentialsMessage = "Tên đăng nhập hoặc mật khẩu không chính xác.";
    private const string LockoutMessage = "Tài khoản đã bị tạm khóa do đăng nhập sai quá nhiều lần. Vui lòng thử lại sau.";
    private const int MaxFailedAccessAttempts = 5;
    private static readonly TimeSpan DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);

    private readonly ApplicationDbContext _context;
    private readonly IAccountPasswordService _passwordService;
    private readonly ISystemAuditService _auditService;

    public AccountController(
        ApplicationDbContext context,
        IAccountPasswordService passwordService,
        ISystemAuditService auditService)
    {
        _context = context;
        _passwordService = passwordService;
        _auditService = auditService;
    }

    [AllowAnonymous]
    [Route("")]
    [Route("Login")]
    [HttpGet]
    public IActionResult Login()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToDashboard(User.FindFirstValue(ClaimTypes.Role));
        }

        if (HttpContext.Items.TryGetValue("NetworkDenied", out var denied)
            && denied is bool deniedFlag
            && deniedFlag)
        {
            ViewBag.NetworkError = "Vui lòng chuyển sang mạng cục bộ của công ty để đăng nhập.";
        }

        return View();
    }

    [AllowAnonymous]
    [Route("Login")]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(
        string username,
        string password,
        CancellationToken cancellationToken)
    {
        username = username?.Trim() ?? string.Empty;

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password))
        {
            ViewBag.Error = "Tên đăng nhập và mật khẩu không được để trống.";
            return View();
        }

        User? user;
        try
        {
            user = await _context.Users.FirstOrDefaultAsync(
                account => account.Username == username || account.Email == username,
                cancellationToken);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            ViewBag.Error = "Không thể kết nối cơ sở dữ liệu. Vui lòng thử lại sau.";
            return View();
        }

        if (user is null)
        {
            await TryWriteAuditAsync(
                null,
                "login_failed",
                $"Đăng nhập thất bại với định danh không tồn tại: {Truncate(username, 100)}.",
                cancellationToken);
            ViewBag.Error = InvalidCredentialsMessage;
            return View();
        }

        if (!string.Equals(user.Status, AccountStatuses.Active, StringComparison.Ordinal))
        {
            await TryWriteAuditAsync(
                user.Id,
                "login_failed",
                $"Tài khoản {user.Username} đang bị khóa.",
                cancellationToken);
            ViewBag.Error = "Tài khoản đang bị khóa.";
            return View();
        }

        var matchedUserId = user.Id;
        var matchedUsername = user.Username;

        try
        {
            user = await VerifyAndUpgradePasswordAsync(user, password, cancellationToken);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            ViewBag.Error = "Không thể hoàn tất đăng nhập. Vui lòng thử lại sau.";
            return View();
        }

        if (user is null)
        {
            await TryWriteAuditAsync(
                matchedUserId,
                "login_failed",
                $"Sai mật khẩu tài khoản {matchedUsername}.",
                cancellationToken);
            await RecordFailedAttemptAsync(matchedUserId, matchedUsername, cancellationToken);
            ViewBag.Error = InvalidCredentialsMessage;
            return View();
        }

        if (await IsLockedOutAsync(user, cancellationToken))
        {
            await TryWriteAuditAsync(
                user.Id,
                "login_blocked_locked",
                $"Login blocked — account locked until {user.LockoutEndUtc:O} (UTC)",
                cancellationToken);
            ViewBag.Error = LockoutMessage;
            return View();
        }

        if (ResetLockoutState(user))
        {
            try
            {
                await _context.SaveChangesAsync(cancellationToken);
            }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
            }
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString(CultureInfo.InvariantCulture)),
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Role, user.Role),
            new(SecurityClaimTypes.SecurityStamp, user.SecurityStamp.ToString("D"))
        };

        var claimsIdentity = new ClaimsIdentity(
            claims,
            CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.AddHours(2),
            AllowRefresh = true
        };

        await TryWriteAuditAsync(
            user.Id,
            "login_succeeded",
            $"Tài khoản {user.Username} đăng nhập thành công.",
            cancellationToken);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);

        return RedirectToDashboard(user.Role);
    }

    [Authorize]
    [Route("Logout")]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout(CancellationToken cancellationToken)
    {
        var identifier = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (int.TryParse(identifier, NumberStyles.None, CultureInfo.InvariantCulture, out var userId))
        {
            await TryWriteAuditAsync(
                userId,
                "logout",
                $"Tài khoản {User.Identity?.Name} đăng xuất.",
                cancellationToken);
        }

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction(nameof(Login));
    }

    [AllowAnonymous]
    [Route("AccessDenied")]
    [HttpGet]
    public IActionResult AccessDenied() => View();

    private async Task<User?> VerifyAndUpgradePasswordAsync(
        User user,
        string password,
        CancellationToken cancellationToken)
    {
        const int maxAttempts = 2;

        for (var attempt = 0; attempt < maxAttempts; attempt++)
        {
            if (!string.Equals(user.Status, AccountStatuses.Active, StringComparison.Ordinal))
            {
                return null;
            }

            var verification = _passwordService.VerifyPassword(user, password);
            if (verification == PasswordVerificationStatus.Failed)
            {
                return null;
            }

            var mustPersistSecurityState =
                verification == PasswordVerificationStatus.SuccessRehashNeeded ||
                user.SecurityStamp == Guid.Empty;

            if (!mustPersistSecurityState)
            {
                return user;
            }

            if (verification == PasswordVerificationStatus.SuccessRehashNeeded)
            {
                user.PasswordHash = _passwordService.HashPassword(user, password);
            }

            user.SecurityStamp = Guid.NewGuid();
            user.UpdatedAt = DateTime.Now;

            try
            {
                await _context.SaveChangesAsync(cancellationToken);
                return user;
            }
            catch (DbUpdateConcurrencyException) when (attempt + 1 < maxAttempts)
            {
                _context.ChangeTracker.Clear();
                var reloadedUser = await _context.Users.FirstOrDefaultAsync(
                    account => account.Id == user.Id,
                    cancellationToken);

                if (reloadedUser is null)
                {
                    return null;
                }

                user = reloadedUser;
            }
        }

        return null;
    }

    private IActionResult RedirectToDashboard(string? role)
        => role switch
        {
            AppRoles.Director => RedirectToAction("Dashboard", "Director"),
            AppRoles.AdminIT => RedirectToAction("Dashboard", "AdminIT"),
            AppRoles.HumanResourcesManager => RedirectToAction("HumanResources", "ManageHuman"),
            AppRoles.HumanResourcesStaff => RedirectToAction("HumanResources", "HumanResourcesStaff"),
            AppRoles.BookingManager => RedirectToAction("Dashboard", "ManageBooking"),
            AppRoles.BookingStaff => RedirectToAction("Booking", "BookingStaff"),
            AppRoles.IdeaManager => RedirectToAction("Dashboard", "ManageIdea"),
            AppRoles.IdeaStaff => RedirectToAction("Idea", "IdeaStaff"),
            _ => RedirectToAction("Index", "Home")
        };

    private async Task TryWriteAuditAsync(
        int? userId,
        string actionType,
        string detail,
        CancellationToken cancellationToken)
    {
        try
        {
            _auditService.AddAccountEvent(userId, actionType, detail);
            await _context.SaveChangesAsync(cancellationToken);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            // Authentication must remain available even when audit persistence is temporarily unavailable.
        }
    }

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];

    private async Task<bool> IsLockedOutAsync(User user, CancellationToken cancellationToken)
    {
        if (!user.LockoutEndUtc.HasValue)
        {
            return false;
        }

        if (user.LockoutEndUtc.Value > DateTime.UtcNow)
        {
            return true;
        }

        user.LockoutEndUtc = null;
        user.AccessFailedCount = 0;
        return false;
    }

    private static bool ResetLockoutState(User user)
    {
        if (user.AccessFailedCount == 0 && !user.LockoutEndUtc.HasValue)
        {
            return false;
        }

        user.AccessFailedCount = 0;
        user.LockoutEndUtc = null;
        return true;
    }

    private async Task RecordFailedAttemptAsync(int userId, string username, CancellationToken cancellationToken)
    {
        User? user;
        try
        {
            user = await _context.Users.FirstOrDefaultAsync(
                account => account.Id == userId,
                cancellationToken);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return;
        }

        if (user is null)
        {
            return;
        }

        user.AccessFailedCount += 1;
        user.UpdatedAt = DateTime.UtcNow;

        if (user.AccessFailedCount >= MaxFailedAccessAttempts)
        {
            user.LockoutEndUtc = DateTime.UtcNow.Add(DefaultLockoutTimeSpan);

            await TryWriteAuditAsync(
                user.Id,
                "account_locked",
                $"Tài khoản {username} bị khóa sau {user.AccessFailedCount} lần đăng nhập sai cho đến {user.LockoutEndUtc:O} (UTC).",
                cancellationToken);
        }

        try
        {
            await _context.SaveChangesAsync(cancellationToken);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
        }
    }
}

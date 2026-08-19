using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using System.Net;

namespace HanaMedia.Middlewares;

public class IpWhitelistMiddleware
{
    private const string NetworkDeniedItemKey = "NetworkDenied";
    private const string LogoutPath = "/Logout";
    private const string LoginPath = "/Login";
    private const string NetworkDeniedMessage = "Vui lòng kết nối mạng nội bộ công ty để sử dụng hệ thống.";

    private readonly RequestDelegate _next;
    private readonly ILogger<IpWhitelistMiddleware> _logger;
    private readonly NetworkAccessOptions _options;

    public IpWhitelistMiddleware(
        RequestDelegate next,
        ILogger<IpWhitelistMiddleware> logger,
        IOptions<NetworkAccessOptions> options)
    {
        _next = next;
        _logger = logger;
        _options = options.Value;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;

        if (IsAlwaysAllowed(path))
        {
            await _next(context);
            return;
        }

        var clientIp = ResolveClientIp(context.Connection.RemoteIpAddress, out var normalizationNote);

        var ipAllowed = clientIp != null && TryMatchNetwork(clientIp, out _);

        _logger.LogInformation(
            "NetworkAccessCheck path={Path} method={Method} resolvedClientIp={Resolved} normalization={Norm} allowed={Allowed}",
            path,
            context.Request.Method,
            clientIp?.ToString() ?? "null",
            normalizationNote,
            ipAllowed);

        if (IsLoginEndpoint(path))
        {
            if (!ipAllowed)
            {
                context.Items[NetworkDeniedItemKey] = true;
                _logger.LogWarning(
                    "NETWORK_ACCESS_DENIED path={Path} method={Method} resolvedClientIp={Resolved}",
                    path,
                    context.Request.Method,
                    clientIp?.ToString() ?? "null");
            }

            await _next(context);
            return;
        }

        if (!ipAllowed)
        {
            _logger.LogWarning(
                "NETWORK_ACCESS_DENIED path={Path} method={Method} resolvedClientIp={Resolved}",
                path,
                context.Request.Method,
                clientIp?.ToString() ?? "null");

            await ForceLogoutAsync(context);
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "text/plain; charset=utf-8";
            await context.Response.WriteAsync(NetworkDeniedMessage);
            return;
        }

        await _next(context);
    }

    private static bool IsLoginEndpoint(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }

        return path.Equals(LoginPath, StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(LoginPath + "?", StringComparison.OrdinalIgnoreCase);
    }

    private bool TryMatchNetwork(IPAddress clientIp, out string? matchedCidr)
    {
        matchedCidr = null;
        foreach (var cidr in _options.AllowedCidrs)
        {
            if (string.IsNullOrWhiteSpace(cidr))
            {
                continue;
            }

            try
            {
                if (IpCidr.TryParse(cidr, out var network) && network.Contains(clientIp))
                {
                    matchedCidr = cidr;
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Invalid CIDR in IpWhitelist config: {Cidr}", cidr);
            }
        }

        return false;
    }

    private static bool IsAlwaysAllowed(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return true;
        }

        return path.Equals(LogoutPath, StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(LogoutPath + "?", StringComparison.OrdinalIgnoreCase)
            || path.Equals("/favicon.ico", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/css/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/js/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/lib/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/images/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/fonts/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/_framework/", StringComparison.OrdinalIgnoreCase);
    }

    private static IPAddress? ResolveClientIp(IPAddress? remoteIp, out string note)
    {
        if (remoteIp == null)
        {
            note = "no-remote-ip";
            return null;
        }

        if (remoteIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (IPAddress.IsLoopback(remoteIp))
            {
                note = "ipv6-loopback";
                return IPAddress.Loopback;
            }

            if (remoteIp.IsIPv4MappedToIPv6)
            {
                note = "ipv4-mapped-ipv6";
                return remoteIp.MapToIPv4();
            }
        }

        note = "passthrough";
        return remoteIp;
    }

    private static async Task ForceLogoutAsync(HttpContext context)
    {
        try
        {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
        catch
        {
        }

        foreach (var cookieKey in context.Request.Cookies.Keys)
        {
            if (cookieKey.StartsWith(".AspNetCore.", StringComparison.OrdinalIgnoreCase)
                || cookieKey.Contains("Identity", StringComparison.OrdinalIgnoreCase)
                || cookieKey.Contains("Cookie", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.Cookies.Delete(cookieKey);
            }
        }
    }
}

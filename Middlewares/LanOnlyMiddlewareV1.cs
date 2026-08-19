using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Sockets;

namespace HanaMedia.Middlewares
{
    /// <summary>
    /// Legacy LAN-only network access middleware (kept for backwards compatibility with module 1 v1).
    /// New code should use IpWhitelistMiddleware. This middleware performs the same allow-list
    /// check but additionally emits a NETWORK_ACCESS_DENIED audit log via SecurityAudit.
    /// </summary>
    public class LanOnlyMiddlewareV1
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<LanOnlyMiddlewareV1> _logger;
        private readonly NetworkAccessOptions _options;

        public LanOnlyMiddlewareV1(
            RequestDelegate next,
            ILogger<LanOnlyMiddlewareV1> logger,
            IOptions<NetworkAccessOptions> options)
        {
            _next = next;
            _logger = logger;
            _options = options.Value;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var path = context.Request.Path.Value ?? string.Empty;

            // Always allow static files so the Login page UI (CSS/JS/images) can load
            // even when the network is denied. The 403 + popup logic runs on the
            // HTML endpoint itself, not on static assets.
            if (IsAlwaysAllowed(path))
            {
                await _next(context);
                return;
            }

            var clientIp = ResolveClientIp(context.Connection.RemoteIpAddress, out var normalizationNote);

            bool ipAllowed;
            string? matchedNetwork = null;
            if (clientIp == null)
            {
                ipAllowed = false;
            }
            else
            {
                ipAllowed = TryMatchNetwork(clientIp, out matchedNetwork);
            }

            _logger.LogInformation(
                "NetworkAccessCheck path={Path} method={Method} resolvedClientIp={Resolved} normalization={Norm} matchedNetwork={Matched} allowed={Allowed}",
                path,
                context.Request.Method,
                clientIp?.ToString() ?? "null",
                normalizationNote,
                matchedNetwork ?? "null",
                ipAllowed);

            // The Login endpoint itself must NOT 403 — instead it must render the
            // login page with a network-denied popup. We signal the controller by
            // attaching a server-side flag (HttpContext.Items) so the view can
            // show the modal. The credential check is skipped entirely on
            // network denial.
            if (IsLoginEndpoint(path))
            {
                if (!ipAllowed)
                {
                    context.Items["NetworkDenied"] = true;

                    _logger.LogWarning(
                        "NETWORK_ACCESS_DENIED path={Path} method={Method} resolvedClientIp={Resolved}",
                        path,
                        context.Request.Method,
                        clientIp?.ToString() ?? "null");

                    SecurityAudit.WriteSystemAuditLog(
                        _logger,
                        context,
                        actionType: "NETWORK_ACCESS_DENIED",
                        module: "Auth",
                        userId: null,
                        logDetail: $"Login request from {clientIp?.ToString() ?? "unknown"} blocked (network denied)");
                }

                await _next(context);
                return;
            }

            // For every other protected route, network denial = hard 403.
            if (!ipAllowed)
            {
                _logger.LogWarning(
                    "NETWORK_ACCESS_DENIED path={Path} method={Method} resolvedClientIp={Resolved}",
                    path,
                    context.Request.Method,
                    clientIp?.ToString() ?? "null");

                await ForceLogoutAsync(context);

                SecurityAudit.WriteSystemAuditLog(
                    _logger,
                    context,
                    actionType: "NETWORK_ACCESS_DENIED",
                    module: "Auth",
                    userId: null,
                    logDetail: $"Denied {context.Request.Method} {path} from {clientIp?.ToString() ?? "unknown"}");

                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/plain; charset=utf-8";
                await context.Response.WriteAsync(
                    "Vui lòng kết nối mạng nội bộ công ty để sử dụng hệ thống.");
                return;
            }

            await _next(context);
        }

        private static bool IsLoginEndpoint(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            return path.Equals("/Login", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/Login?", StringComparison.OrdinalIgnoreCase);
        }

        private bool TryMatchNetwork(IPAddress clientIp, out string? matchedCidr)
        {
            matchedCidr = null;
            foreach (var cidr in _options.AllowedCidrs)
            {
                if (string.IsNullOrWhiteSpace(cidr)) continue;
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

            return path.Equals("/Logout", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/Logout?", StringComparison.OrdinalIgnoreCase)
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

            if (remoteIp.AddressFamily == AddressFamily.InterNetworkV6)
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
}

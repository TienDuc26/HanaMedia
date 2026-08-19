using System.Security.Claims;

namespace HanaMedia.Middlewares
{
    public static class SecurityAudit
    {
        public static void WriteSystemAuditLog(
            ILogger logger,
            HttpContext context,
            string actionType,
            string module,
            int? userId,
            string logDetail)
        {
            var ip = context.Connection.RemoteIpAddress?.ToString();
            if (!string.IsNullOrEmpty(ip) && ip.StartsWith("::ffff:"))
            {
                ip = ip.Substring(7);
            }

            if (string.IsNullOrEmpty(ip))
            {
                ip = "unknown";
            }

            var userAgent = context.Request.Headers.UserAgent.ToString();
            if (userAgent.Length > 250)
            {
                userAgent = userAgent.Substring(0, 250);
            }

            if (userId == null && context.User?.Identity?.IsAuthenticated == true)
            {
                var sub = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (int.TryParse(sub, out var parsed))
                {
                    userId = parsed;
                }
            }

            logger.LogInformation(
                "AUDIT action={Action} module={Module} userId={UserId} ip={Ip} detail={Detail}",
                actionType,
                module,
                userId?.ToString() ?? "-",
                ip,
                logDetail);
        }
    }
}

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace AuthentiChip
{
    /// <summary>
    /// ASP.NET Core middleware for AuthentiChip JWT validation
    /// </summary>
    public class AuthentiChipMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<AuthentiChipMiddleware> _logger;

        public AuthentiChipMiddleware(RequestDelegate next, ILogger<AuthentiChipMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var vkjwt = context.Request.Query["vkjwt"].ToString();
            var vkstatus = context.Request.Query["vkstatus"].ToString();
            var vkuid = context.Request.Query["vkuid"].ToString();

            // Initialize context items
            context.Items["ChipVerified"] = false;
            context.Items["ChipStatus"] = ChipStatus.None;

            // Attempt JWT validation
            if (!string.IsNullOrEmpty(vkjwt))
            {
                try
                {
                    var chipId = await JwtValidator.ValidateAsync(vkjwt);

                    context.Items["ChipId"] = chipId;
                    context.Items["ChipVerified"] = true;
                    context.Items["ChipStatus"] = ChipStatus.Verified;

                    _logger.LogInformation(
                        "[AuthentiChip] Verified: {ChipId} from {RemoteIp}",
                        chipId,
                        context.Connection.RemoteIpAddress
                    );
                }
                catch (Exception ex)
                {
                    var status = DetermineStatus(ex.Message);
                    context.Items["ChipStatus"] = status;

                    _logger.LogWarning(
                        "[AuthentiChip] Validation failed: {Error} from {RemoteIp}",
                        ex.Message,
                        context.Connection.RemoteIpAddress
                    );
                }
            }
            // Handle unverified scans
            else if (!string.IsNullOrEmpty(vkstatus) && !string.IsNullOrEmpty(vkuid))
            {
                context.Items["ChipUid"] = vkuid;
                context.Items["ChipStatus"] = ParseStatus(vkstatus);
                context.Items["ChipVerified"] = false;

                _logger.LogInformation(
                    "[AuthentiChip] Unverified scan: UID={Uid}, Status={Status} from {RemoteIp}",
                    vkuid,
                    vkstatus,
                    context.Connection.RemoteIpAddress
                );
            }

            await _next(context);
        }

        private static ChipStatus DetermineStatus(string errorMessage)
        {
            var lower = errorMessage.ToLowerInvariant();

            if (lower.Contains("expired"))
                return ChipStatus.Expired;
            if (lower.Contains("signature"))
                return ChipStatus.Invalid;

            return ChipStatus.Error;
        }

        private static ChipStatus ParseStatus(string status)
        {
            return status.ToLowerInvariant() switch
            {
                "insecure" => ChipStatus.Insecure,
                "expired" => ChipStatus.Expired,
                "invalid" => ChipStatus.Invalid,
                _ => ChipStatus.None
            };
        }
    }

    /// <summary>
    /// Endpoint filter that requires valid AuthentiChip authentication
    /// </summary>
    public class RequireAuthentiChipFilter : IEndpointFilter
    {
        private readonly ILogger<RequireAuthentiChipFilter> _logger;

        public RequireAuthentiChipFilter(ILogger<RequireAuthentiChipFilter> logger)
        {
            _logger = logger;
        }

        public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        {
            var httpContext = context.HttpContext;
            var chipVerified = httpContext.Items["ChipVerified"] as bool? ?? false;

            if (!chipVerified)
            {
                var status = httpContext.Items["ChipStatus"] as ChipStatus? ?? ChipStatus.None;
                var message = status switch
                {
                    ChipStatus.Expired => "This scan is too old. Please scan again.",
                    ChipStatus.Invalid => "This chip could not be verified.",
                    ChipStatus.None => "No chip authentication provided.",
                    _ => "Unable to verify chip."
                };

                _logger.LogWarning(
                    "[AuthentiChip] Required but not verified (status: {Status}) from {RemoteIp}",
                    status,
                    httpContext.Connection.RemoteIpAddress
                );

                return Results.Json(
                    new
                    {
                        error = "Authentication required",
                        message,
                        status = status.ToString().ToLowerInvariant()
                    },
                    statusCode: 401
                );
            }

            return await next(context);
        }
    }

    /// <summary>
    /// Action filter attribute for MVC controllers that requires authentication
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class RequireAuthentiChipAttribute : Microsoft.AspNetCore.Mvc.TypeFilterAttribute
    {
        public RequireAuthentiChipAttribute() : base(typeof(RequireAuthentiChipActionFilter))
        {
        }
    }

    /// <summary>
    /// MVC action filter implementation
    /// </summary>
    public class RequireAuthentiChipActionFilter : Microsoft.AspNetCore.Mvc.Filters.IActionFilter
    {
        private readonly ILogger<RequireAuthentiChipActionFilter> _logger;

        public RequireAuthentiChipActionFilter(ILogger<RequireAuthentiChipActionFilter> logger)
        {
            _logger = logger;
        }

        public void OnActionExecuting(Microsoft.AspNetCore.Mvc.Filters.ActionExecutingContext context)
        {
            var httpContext = context.HttpContext;
            var chipVerified = httpContext.Items["ChipVerified"] as bool? ?? false;

            if (!chipVerified)
            {
                var status = httpContext.Items["ChipStatus"] as ChipStatus? ?? ChipStatus.None;
                var message = status switch
                {
                    ChipStatus.Expired => "This scan is too old. Please scan again.",
                    ChipStatus.Invalid => "This chip could not be verified.",
                    ChipStatus.None => "No chip authentication provided.",
                    _ => "Unable to verify chip."
                };

                _logger.LogWarning(
                    "[AuthentiChip] Required but not verified (status: {Status}) from {RemoteIp}",
                    status,
                    httpContext.Connection.RemoteIpAddress
                );

                context.Result = new Microsoft.AspNetCore.Mvc.UnauthorizedObjectResult(new
                {
                    error = "Authentication required",
                    message,
                    status = status.ToString().ToLowerInvariant()
                });
            }
        }

        public void OnActionExecuted(Microsoft.AspNetCore.Mvc.Filters.ActionExecutedContext context)
        {
            // No action needed after execution
        }
    }
}

namespace Microsoft.Extensions.DependencyInjection
{
    using Microsoft.AspNetCore.Builder;

    /// <summary>
    /// Extension methods for adding AuthentiChip middleware
    /// </summary>
    public static class AuthentiChipExtensions
    {
        /// <summary>
        /// Add AuthentiChip middleware to the application pipeline
        /// </summary>
        public static IApplicationBuilder UseAuthentiChip(this IApplicationBuilder app)
        {
            return app.UseMiddleware<AuthentiChip.AuthentiChipMiddleware>();
        }
    }
}

using AuthentiChip;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthentiChip.Examples
{
    /// <summary>
    /// Example .NET 6+ minimal API application with AuthentiChip integration
    /// </summary>
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services
            builder.Services.AddLogging();

            var app = builder.Build();

            // Add AuthentiChip middleware
            app.UseAuthentiChip();

            // Example 1: Simple endpoint with optional authentication
            app.MapGet("/", (HttpContext context) =>
            {
                var chipVerified = context.Items["ChipVerified"] as bool? ?? false;
                var chipId = context.Items["ChipId"] as string;
                var chipStatus = context.Items["ChipStatus"] as ChipStatus?;

                return Results.Ok(new
                {
                    chipVerified,
                    chipId,
                    chipStatus = chipStatus?.ToString().ToLowerInvariant(),
                    message = chipVerified
                        ? $"Welcome! Verified chip: {chipId}"
                        : "No verified chip detected"
                });
            });

            // Example 2: Product endpoint with optional authentication
            app.MapGet("/product/{id}", (string id, HttpContext context) =>
            {
                var chipVerified = context.Items["ChipVerified"] as bool? ?? false;
                var chipId = context.Items["ChipId"] as string;
                var chipStatus = context.Items["ChipStatus"] as ChipStatus?;
                var chipUid = context.Items["ChipUid"] as string;

                var product = new
                {
                    id,
                    name = "Example Product",
                    verified = chipVerified,
                    chipId,
                    chipUid,
                    status = chipStatus?.ToString().ToLowerInvariant(),
                    message = chipVerified
                        ? "This is a verified authentic product"
                        : (chipStatus == ChipStatus.Insecure || chipStatus == ChipStatus.Expired)
                            ? "Verification was unavailable"
                            : "No chip scan detected"
                };

                return Results.Ok(product);
            });

            // Example 3: Protected endpoint with required authentication
            app.MapGet("/protected", (HttpContext context) =>
            {
                var chipId = context.Items["ChipId"] as string;
                return Results.Ok(new
                {
                    message = "Access granted",
                    chipId
                });
            })
            .AddEndpointFilter<RequireAuthentiChipFilter>();

            // Example 4: Multiple protected endpoints using route group
            var protectedGroup = app.MapGroup("/api/protected")
                .AddEndpointFilter<RequireAuthentiChipFilter>();

            protectedGroup.MapGet("/data", (HttpContext context) =>
            {
                var chipId = context.Items["ChipId"] as string;
                return Results.Ok(new
                {
                    chipId,
                    data = "Sensitive data here"
                });
            });

            protectedGroup.MapGet("/profile", (HttpContext context) =>
            {
                var chipId = context.Items["ChipId"] as string;
                return Results.Ok(new
                {
                    chipId,
                    profile = "User profile information"
                });
            });

            // Example 5: Optional authentication with different access levels
            app.MapGet("/content", (HttpContext context) =>
            {
                var chipVerified = context.Items["ChipVerified"] as bool? ?? false;
                var chipId = context.Items["ChipId"] as string;

                if (chipVerified)
                {
                    return Results.Ok(new
                    {
                        level = "premium",
                        chipId,
                        content = "Full access to premium content"
                    });
                }
                else
                {
                    return Results.Ok(new
                    {
                        level = "basic",
                        content = "Limited access to basic content"
                    });
                }
            });

            // Example 6: Direct validation without middleware
            app.MapGet("/validate", async (HttpContext context) =>
            {
                var vkjwt = context.Request.Query["vkjwt"].ToString();
                var vkstatus = context.Request.Query["vkstatus"].ToString();
                var vkuid = context.Request.Query["vkuid"].ToString();

                if (!string.IsNullOrEmpty(vkjwt))
                {
                    var (success, chipId, error) = await JwtValidator.TryValidateAsync(vkjwt);

                    if (success)
                    {
                        return Results.Ok(new
                        {
                            verified = true,
                            chipId
                        });
                    }
                    else
                    {
                        return Results.Json(
                            new { verified = false, error },
                            statusCode: 401
                        );
                    }
                }
                else if (!string.IsNullOrEmpty(vkstatus) && !string.IsNullOrEmpty(vkuid))
                {
                    return Results.Ok(new
                    {
                        verified = false,
                        vkstatus,
                        vkuid,
                        message = vkstatus == "insecure"
                            ? "Verification API was unavailable"
                            : "Chip signature expired"
                    });
                }
                else
                {
                    return Results.BadRequest(new
                    {
                        error = "No authentication parameters provided"
                    });
                }
            });

            // Example 7: Health check endpoint
            app.MapGet("/health", () => Results.Ok(new
            {
                status = "healthy",
                service = "AuthentiChip Example API"
            }));

            app.MapGet("/", () => "AuthentiChip Example API - See /swagger for endpoints");

            app.Run();
        }
    }
}

/*
 * Usage Examples:
 *
 * Test URLs:
 * https://localhost:5001?vkjwt=<token>
 * https://localhost:5001/product/123?vkjwt=<token>
 * https://localhost:5001/product/123?vkuid=ABC&vkstatus=insecure
 * https://localhost:5001/protected?vkjwt=<token>
 * https://localhost:5001/api/protected/data?vkjwt=<token>
 * https://localhost:5001/content?vkjwt=<token>
 * https://localhost:5001/validate?vkjwt=<token>
 *
 * Run with:
 * dotnet run
 *
 * Or build and run:
 * dotnet build
 * dotnet bin/Debug/net8.0/authentichip-examples.dll
 */

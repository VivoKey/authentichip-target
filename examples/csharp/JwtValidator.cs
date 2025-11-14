using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace AuthentiChip
{
    /// <summary>
    /// Validates AuthentiChip JWT tokens
    /// </summary>
    public static class JwtValidator
    {
        private const string JwksUrl = "https://auth.vivokey.com/.well-known/jwks.json";
        private const string Issuer = "auth.vivokey.com";
        private static readonly TimeSpan JwksCacheDuration = TimeSpan.FromHours(6);

        private static ConfigurationManager<OpenIdConnectConfiguration>? _configurationManager;
        private static readonly object _lock = new();

        /// <summary>
        /// UUID validation regex
        /// </summary>
        private static readonly Regex UuidRegex = new(
            @"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        );

        /// <summary>
        /// Get or create the JWKS configuration manager
        /// </summary>
        private static ConfigurationManager<OpenIdConnectConfiguration> GetConfigurationManager()
        {
            if (_configurationManager != null)
            {
                return _configurationManager;
            }

            lock (_lock)
            {
                if (_configurationManager == null)
                {
                    var httpClient = new HttpClient();
                    var documentRetriever = new HttpDocumentRetriever(httpClient)
                    {
                        RequireHttps = true
                    };

                    _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                        JwksUrl,
                        new OpenIdConnectConfigurationRetriever(),
                        documentRetriever
                    )
                    {
                        AutomaticRefreshInterval = JwksCacheDuration,
                        RefreshInterval = JwksCacheDuration
                    };
                }
            }

            return _configurationManager;
        }

        /// <summary>
        /// Validate an AuthentiChip JWT and extract the chip ID
        /// </summary>
        /// <param name="token">The JWT token from vkjwt parameter</param>
        /// <returns>The verified chip ID (UUID)</returns>
        /// <exception cref="ArgumentException">If token is null or empty</exception>
        /// <exception cref="SecurityTokenException">If validation fails</exception>
        public static async Task<string> ValidateAsync(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new ArgumentException("JWT token is required", nameof(token));
            }

            try
            {
                // Get JWKS configuration
                var configManager = GetConfigurationManager();
                var config = await configManager.GetConfigurationAsync();

                // Set up validation parameters
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = Issuer,

                    ValidateAudience = false, // AuthentiChip JWTs don't have audience

                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = config.SigningKeys,

                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromSeconds(10),

                    RequireExpirationTime = true,
                    RequireSignedTokens = true
                };

                // Validate and decode the token
                var tokenHandler = new JwtSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

                // Extract chip ID from subject claim
                var chipId = principal.FindFirst("sub")?.Value;

                if (string.IsNullOrEmpty(chipId))
                {
                    throw new SecurityTokenException("Missing subject (chip ID) in JWT");
                }

                // Validate chip ID format (UUID)
                if (!UuidRegex.IsMatch(chipId))
                {
                    throw new SecurityTokenException("Invalid chip ID format");
                }

                return chipId;
            }
            catch (SecurityTokenExpiredException)
            {
                throw new SecurityTokenException("JWT has expired - scan is too old");
            }
            catch (SecurityTokenInvalidSignatureException)
            {
                throw new SecurityTokenException("JWT signature validation failed - possible tampering");
            }
            catch (SecurityTokenInvalidIssuerException)
            {
                throw new SecurityTokenException("Invalid issuer - expected auth.vivokey.com");
            }
            catch (Exception ex) when (ex is not SecurityTokenException && ex is not ArgumentException)
            {
                throw new SecurityTokenException($"JWT validation failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Try to validate a JWT without throwing exceptions
        /// </summary>
        /// <param name="token">The JWT token</param>
        /// <param name="chipId">The extracted chip ID if successful</param>
        /// <returns>True if validation succeeded, false otherwise</returns>
        public static async Task<(bool Success, string? ChipId, string? Error)> TryValidateAsync(string token)
        {
            try
            {
                var chipId = await ValidateAsync(token);
                return (true, chipId, null);
            }
            catch (Exception ex)
            {
                return (false, null, ex.Message);
            }
        }
    }

    /// <summary>
    /// Chip verification status
    /// </summary>
    public enum ChipStatus
    {
        None,
        Verified,
        Expired,
        Invalid,
        Insecure,
        Error
    }

    /// <summary>
    /// Result of chip authentication
    /// </summary>
    public class ChipAuthResult
    {
        public bool Verified { get; set; }
        public string? ChipId { get; set; }
        public string? ChipUid { get; set; }
        public ChipStatus Status { get; set; }
        public string? ErrorMessage { get; set; }
    }
}

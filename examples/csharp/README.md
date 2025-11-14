# C# / .NET - AuthentiChip JWT Validation

Examples for validating AuthentiChip JWTs in .NET applications.

## Requirements

- .NET 6.0 or higher (.NET 8.0 recommended)
- NuGet package manager

## Dependencies

Install the required packages:

```bash
dotnet add package Microsoft.IdentityModel.Tokens
dotnet add package System.IdentityModel.Tokens.Jwt
```

Or add to your .csproj file:

```xml
<ItemGroup>
    <PackageReference Include="Microsoft.IdentityModel.Tokens" Version="7.0.0" />
    <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="7.0.0" />
</ItemGroup>
```

## Files

- `JwtValidator.cs` - Standalone JWT validation class
- `Middleware.cs` - ASP.NET Core middleware
- `MinimalApiExample.cs` - .NET 6+ minimal API examples
- `authentichip-examples.csproj` - Project file

## Quick Start

### Standalone Usage

```csharp
using AuthentiChip;

// In your controller or minimal API
app.MapGet("/product/{id}", async (string id, HttpContext context) =>
{
    var vkjwt = context.Request.Query["vkjwt"].ToString();
    var vkstatus = context.Request.Query["vkstatus"].ToString();
    var vkuid = context.Request.Query["vkuid"].ToString();

    if (!string.IsNullOrEmpty(vkjwt))
    {
        try
        {
            var chipId = await JwtValidator.ValidateAsync(vkjwt);
            return Results.Ok(new { verified = true, chipId });
        }
        catch (Exception ex)
        {
            return Results.Unauthorized(new { error = ex.Message });
        }
    }
    else if (!string.IsNullOrEmpty(vkstatus) && !string.IsNullOrEmpty(vkuid))
    {
        return Results.Ok(new { verified = false, vkstatus, vkuid });
    }

    return Results.BadRequest(new { error = "No authentication parameters" });
});
```

### ASP.NET Core Middleware

Add to your Program.cs or Startup.cs:

```csharp
using AuthentiChip;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Add middleware
app.UseAuthentiChip();

// Optional authentication - check context items
app.MapGet("/product/{id}", (string id, HttpContext context) =>
{
    var chipVerified = context.Items["ChipVerified"] as bool? ?? false;
    var chipId = context.Items["ChipId"] as string;

    if (chipVerified)
    {
        return Results.Ok(new
        {
            verified = true,
            chipId,
            product = "Full details"
        });
    }

    return Results.Ok(new
    {
        verified = false,
        product = "Limited info"
    });
});

// Required authentication - use endpoint filter
app.MapGet("/protected", (HttpContext context) =>
{
    var chipId = context.Items["ChipId"] as string;
    return Results.Ok(new { chipId, message = "Access granted" });
})
.AddEndpointFilter<RequireAuthentiChipFilter>();

app.Run();
```

### MVC Controller

```csharp
using Microsoft.AspNetCore.Mvc;
using AuthentiChip;

[ApiController]
[Route("[controller]")]
public class ProductController : ControllerBase
{
    [HttpGet("{id}")]
    public async Task<IActionResult> GetProduct(string id)
    {
        var chipVerified = HttpContext.Items["ChipVerified"] as bool? ?? false;
        var chipId = HttpContext.Items["ChipId"] as string;

        if (chipVerified)
        {
            return Ok(new
            {
                verified = true,
                chipId,
                productId = id,
                details = "Full product information"
            });
        }

        return Ok(new
        {
            verified = false,
            productId = id,
            details = "Limited information"
        });
    }

    [HttpGet("protected")]
    [ServiceFilter(typeof(RequireAuthentiChipAttribute))]
    public IActionResult Protected()
    {
        var chipId = HttpContext.Items["ChipId"] as string;
        return Ok(new { chipId, message = "Access granted" });
    }
}
```

## Security Notes

- Always validate JWT signatures - never trust without verification
- Use HTTPS in production to prevent token interception
- JWKS responses are cached automatically
- Set appropriate timeout values for HTTP requests
- Log validation failures for security monitoring
- Use HttpContext.Items to pass chip data between middleware and endpoints

## Testing

Run the example application:

```bash
dotnet run
```

Then access:
```
https://localhost:5001?vkjwt=<token>
https://localhost:5001/product/123?vkuid=ABC&vkstatus=insecure
https://localhost:5001/protected?vkjwt=<token>
```

## Common Issues

**"Unable to fetch JWKS" error**: Network connectivity issue or auth.vivokey.com is unreachable. Check firewall and internet connection.

**"Token is expired" error**: JWT has exceeded its 5-minute validity window. Normal for old scans.

**"Signature validation failed" error**: JWT signature verification failed. Could indicate tampering or incorrect public key.

**Missing packages**: Run `dotnet restore` to install dependencies.

## Configuration

You can configure caching behavior in appsettings.json:

```json
{
  "AuthentiChip": {
    "JwksUrl": "https://auth.vivokey.com/.well-known/jwks.json",
    "JwksCacheDuration": "06:00:00",
    "Issuer": "auth.vivokey.com"
  }
}
```

## Performance

The JWT validation uses Microsoft's optimized JWT libraries with automatic JWKS caching. Typical validation takes < 1ms after initial JWKS fetch.

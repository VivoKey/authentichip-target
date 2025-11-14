# AuthentiChip Target URL Examples

Code examples and integration guides for websites receiving AuthentiChip scan redirects.

## Overview

When a customer scans an AuthentiChip-enabled NFC tag, they are redirected to your website with query parameters containing verification information, generally in the form of a signed JSON Web Token (JWT). This repository provides reference implementations for validating and consuming these parameters across different platforms and languages.

## What is AuthentiChip?

AuthentiChip is an NFC-based authentication system that uses cryptographically signed challenges to verify the authenticity of physical items. When a chip is scanned, the AuthentiChip server validates the signature and redirects the customer to your configured target URL with verification parameters.

## Query Parameters

Your target URL will receive one of the following parameter sets depending on the scan result:

### Success - Valid Signature

```
https://your-site.com?vkjwt=eyJhbGc...
```

- `vkjwt`: JWT (JSON Web Token) containing verified chip information
  - **Issuer**: `auth.vivokey.com`
  - **Subject**: Unique chip ID (UUID format)
  - **Expiration**: 5 minutes from scan time
  - **Algorithm**: RS256 (RSA + SHA-256)

### Insecure - API Unavailable

```
https://your-site.com?vkuid=ABC123&vkstatus=insecure
```

- `vkuid`: Chip UID (unverified, for reference only)
- `vkstatus`: `insecure` - verification API was unavailable

**Warning**: This scenario only occurs if the item owner has explicitly enabled "forward on insecure" in their organization settings. Treat these scans as unverified.

### Expired - Stale Signature

```
https://your-site.com?vkuid=ABC123&vkstatus=expired
```

- `vkuid`: Chip UID (unverified, for reference only)
- `vkstatus`: `expired` - scan signature expired before validation

**Warning**: This scenario only occurs if the item owner has explicitly enabled "forward on expired" in their organization settings. The scan may be a replay attack.

## Security Considerations

### JWT Validation (vkjwt)

When you receive a `vkjwt` parameter, you **MUST**:

1. **Verify the JWT signature** using the public key from `https://auth.vivokey.com/.well-known/jwks.json`
2. **Validate the issuer** matches `auth.vivokey.com`
3. **Check expiration** - reject expired tokens
4. **Verify the algorithm** is RS256 - reject unsigned or HMAC-signed tokens
5. **Extract the subject (sub)** claim - this is the verified chip ID

**Never trust the JWT without signature validation.** An attacker could forge a JWT if you skip verification.

### Insecure/Expired Status

When you receive `vkstatus=insecure` or `vkstatus=expired`:

- **Do not treat as authenticated** - no cryptographic proof of authenticity
- **Use for informational purposes only** - log the scan, show item info, etc.
- **Do not grant access** to sensitive features or data
- **Consider rate limiting** to prevent abuse

The `vkuid` in these scenarios is the raw chip UID, which can be cloned or replayed.

### Existing Query Parameters

The AuthentiChip system will **append** parameters to your target URL:

- `https://your-site.com` becomes `https://your-site.com?vkjwt=...`
- `https://your-site.com?ref=email` becomes `https://your-site.com?ref=email&vkjwt=...`

Your integration must handle existing parameters correctly.

### Reserved Parameter Names

Do not use these parameter names in your target URL configuration:

- `vkjwt`
- `vkuid`
- `vkstatus`

The AuthentiChip system blocks target URLs containing these as existing parameters to prevent conflicts. Using these values in paths or as parameter values is allowed:

- Blocked: `https://your-site.com?vkjwt=something`
- Allowed: `https://your-site.com/vkjwt`
- Allowed: `https://your-site.com?accept=vkjwt`

## Examples

### Node.js / JavaScript

See [examples/nodejs](examples/nodejs) for:
- Express.js middleware for JWT validation
- Next.js API route handler
- React component for displaying verified chip info
- Vanilla JavaScript browser-side validation

### Python

See [examples/python](examples/python) for:
- Flask request handler
- Django middleware
- FastAPI dependency injection

### PHP

See [examples/php](examples/php) for:
- Laravel middleware
- WordPress plugin integration
- Standalone validation function

### Go

See [examples/go](examples/go) for:
- HTTP middleware
- gin-gonic handler
- Standalone validation package

### Ruby

See [examples/ruby](examples/ruby) for:
- Rails controller concern
- Sinatra middleware
- Standalone validation gem

## Quick Start

1. Choose the example matching your platform
2. Install required dependencies (JWT library, HTTP client)
3. Fetch the public key from `https://auth.vivokey.com/.well-known/jwks.json`
4. Validate incoming JWTs according to security guidelines above
5. Extract the chip ID from the `sub` claim
6. Use the chip ID to look up item information, grant access, etc.

## Testing

To test your integration:

1. Register for an AuthentiChip account at [https://authentichip.com](https://authentichip.com)
2. Configure your test target URL
3. Register a test chip
4. Scan the chip and verify your endpoint receives the parameters
5. Test all three scenarios: success, insecure (if enabled), expired (if enabled)

## Public Key Retrieval

The RS256 public keys are available at:

```
https://auth.vivokey.com/.well-known/jwks.json
```

This endpoint returns a JSON Web Key Set (JWKS) in standard format. Cache this response with a reasonable TTL (1-24 hours) to avoid rate limiting.

Example response structure:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "...",
      "n": "...",
      "e": "AQAB",
      "alg": "RS256",
      "use": "sig"
    }
  ]
}
```

## JWT Structure

A valid `vkjwt` contains:

**Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-identifier"
}
```

**Payload:**
```json
{
  "iss": "auth.vivokey.com",
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "iat": 1699900000,
  "exp": 1699900300
}
```

- `iss`: Issuer - always `auth.vivokey.com`
- `sub`: Subject - unique chip ID (UUID)
- `iat`: Issued at timestamp (Unix epoch)
- `exp`: Expiration timestamp (Unix epoch, 5 minutes after iat)

## Contributing

Contributions are welcome! To add an example:

1. Fork this repository
2. Create a new directory under `examples/` for your language/framework
3. Include working code with comments explaining each step
4. Add a README.md in your example directory with setup instructions
5. Test your example thoroughly
6. Submit a pull request

## Support

- **Documentation**: [https://docs.authentichip.com](https://docs.authentichip.com)
- **Issues**: Report problems or request examples via GitHub Issues
- **Security**: Report security vulnerabilities privately to security@vivokey.com

## License

This repository is dedicated to the public domain under CC0 1.0 Universal. You may use, modify, and distribute these examples without restriction or attribution. See [LICENSE](LICENSE) for details.

## Disclaimer

These examples are provided as-is for educational and integration purposes. While we strive for accuracy and security best practices, you are responsible for validating that your implementation meets your security requirements. Always perform your own security review before deploying to production.

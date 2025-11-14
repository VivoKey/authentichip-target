# PHP - AuthentiChip JWT Validation

Examples for validating AuthentiChip JWTs in PHP applications.

## Requirements

- PHP 7.4 or higher (PHP 8.x recommended)
- Composer for dependency management

## Dependencies

Install the Firebase JWT library:

```bash
composer require firebase/php-jwt
```

## Files

- `validate_jwt.php` - Standalone JWT validation function
- `laravel_middleware.php` - Laravel middleware example
- `wordpress_plugin.php` - WordPress plugin integration example

## Quick Start

### Standalone Usage

```php
require 'vendor/autoload.php';
require 'validate_jwt.php';

// Get the JWT from query string
$jwt = $_GET['vkjwt'] ?? null;

if ($jwt) {
    try {
        $chipId = validateAuthentiChipJWT($jwt);
        echo "Verified chip ID: " . $chipId;

        // Use $chipId to look up item info, grant access, etc.

    } catch (Exception $e) {
        http_response_code(401);
        echo "Invalid chip: " . $e->getMessage();
    }
} else {
    // Check for insecure/expired status
    $status = $_GET['vkstatus'] ?? null;
    $uid = $_GET['vkuid'] ?? null;

    if ($status === 'insecure' || $status === 'expired') {
        // Unverified scan - handle accordingly
        echo "Unverified scan (status: $status, UID: $uid)";
    } else {
        echo "No authentication parameters provided";
    }
}
```

### Laravel

1. Copy `laravel_middleware.php` to `app/Http/Middleware/ValidateAuthentiChip.php`
2. Register the middleware in `app/Http/Kernel.php`
3. Apply to routes:

```php
Route::get('/product/{id}', [ProductController::class, 'show'])
    ->middleware('authentichip');
```

4. Access the chip ID in your controller:

```php
public function show(Request $request, $id)
{
    $chipId = $request->attributes->get('chip_id');
    // $chipId is null for unverified scans

    if ($chipId) {
        // Verified - show full details
    } else {
        // Unverified - limited info only
    }
}
```

### WordPress

1. Copy `wordpress_plugin.php` to `wp-content/plugins/authentichip/`
2. Activate the plugin in WordPress admin
3. Use the action hook in your theme/plugin:

```php
add_action('authentichip_verified', function($chipId) {
    // Handle verified chip scan
    error_log("Verified chip: " . $chipId);
});

add_action('authentichip_unverified', function($uid, $status) {
    // Handle unverified scan
    error_log("Unverified scan - UID: $uid, Status: $status");
}, 10, 2);
```

## Security Notes

- Always validate JWT signatures - never trust without verification
- Use HTTPS for your target URLs to prevent token interception
- Cache the JWKS response (1-24 hours) to reduce API calls
- Reject expired tokens (checked automatically by the library)
- Log failed validation attempts for security monitoring

## Testing

To test your integration:

1. Set up your AuthentiChip target URL pointing to your development server
2. Register a test chip
3. Scan and verify parameters are received correctly
4. Test with an expired/invalid JWT to verify error handling

## Common Issues

**"Unable to parse key" error**: The JWKS endpoint may be unreachable or the response format changed. Check your internet connection and the JWKS URL.

**"Expired token" error**: JWTs expire 5 minutes after issuance. This is normal for old scans.

**"Signature verification failed" error**: The JWT was tampered with or signed by a different key. This should be treated as an attack attempt.

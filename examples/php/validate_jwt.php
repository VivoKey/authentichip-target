<?php
/**
 * AuthentiChip JWT Validation
 *
 * Validates a JWT from the vkjwt query parameter and extracts the verified chip ID.
 *
 * @param string $jwt The JWT token from the vkjwt parameter
 * @return string The verified chip ID (UUID)
 * @throws Exception If validation fails
 */

require 'vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;

/**
 * Fetch and cache the JWKS (JSON Web Key Set) from auth.vivokey.com
 *
 * In production, cache this response for 1-24 hours to avoid rate limiting
 */
function getAuthentiChipJWKS() {
    $jwksUrl = 'https://auth.vivokey.com/.well-known/jwks.json';

    // Simple file-based cache (replace with Redis/Memcached in production)
    $cacheFile = sys_get_temp_dir() . '/authentichip_jwks.json';
    $cacheAge = file_exists($cacheFile) ? (time() - filemtime($cacheFile)) : PHP_INT_MAX;

    // Cache for 6 hours
    if ($cacheAge < 21600 && file_exists($cacheFile)) {
        $jwks = json_decode(file_get_contents($cacheFile), true);
        if ($jwks) {
            return $jwks;
        }
    }

    // Fetch fresh JWKS
    $context = stream_context_create([
        'http' => [
            'timeout' => 10,
            'method' => 'GET',
        ]
    ]);

    $response = @file_get_contents($jwksUrl, false, $context);

    if ($response === false) {
        throw new Exception('Unable to fetch JWKS from auth.vivokey.com');
    }

    $jwks = json_decode($response, true);

    if (!$jwks || !isset($jwks['keys'])) {
        throw new Exception('Invalid JWKS response format');
    }

    // Cache the response
    file_put_contents($cacheFile, $response);

    return $jwks;
}

/**
 * Validate an AuthentiChip JWT and extract the chip ID and UID
 *
 * @param string $jwt The JWT token
 * @return array Associative array with 'chipId' (SHA-256 hash) and 'uid' (7-byte chip UID)
 * @throws Exception If validation fails for any reason
 */
function validateAuthentiChipJWT($jwt) {
    if (empty($jwt)) {
        throw new Exception('JWT token is required');
    }

    try {
        // Fetch the public keys
        $jwks = getAuthentiChipJWKS();

        // Parse JWKS into format expected by Firebase JWT library
        $keys = JWK::parseKeySet($jwks);

        // Decode and validate the JWT
        // This automatically:
        // - Verifies the signature using the public key
        // - Checks the expiration time
        // - Validates the algorithm is in the allowed list
        $decoded = JWT::decode($jwt, $keys);

        // Verify the issuer
        if (!isset($decoded->iss) || $decoded->iss !== 'auth.vivokey.com') {
            throw new Exception('Invalid issuer - expected auth.vivokey.com');
        }

        // Extract the chip ID from the subject claim
        if (!isset($decoded->sub) || empty($decoded->sub)) {
            throw new Exception('Missing subject (chip ID) in JWT');
        }

        $chipId = $decoded->sub;

        // Validate the chip ID format (should be SHA-256 hash - 64 hex characters)
        if (!preg_match('/^[0-9a-f]{64}$/i', $chipId)) {
            throw new Exception('Invalid chip ID format - expected SHA-256 hash');
        }

        // Validate product claim (must be 6 for AuthentiChip)
        if (!isset($decoded->product) || $decoded->product !== 6) {
            throw new Exception('Invalid product claim - expected product=6 for AuthentiChip');
        }

        // Validate audience claim exists
        if (!isset($decoded->aud) || empty($decoded->aud)) {
            throw new Exception('Missing audience (aud) claim in JWT');
        }

        // Extract UID from client data claim
        if (!isset($decoded->cld) || empty($decoded->cld)) {
            throw new Exception('Missing client data (cld) claim');
        }

        // Parse cld as JSON string
        $cldData = json_decode($decoded->cld);
        if ($cldData === null || !isset($cldData->uid) || empty($cldData->uid)) {
            throw new Exception('Missing uid in client data (cld) claim');
        }

        $uid = $cldData->uid;

        return [
            'chipId' => $chipId,
            'uid' => $uid
        ];

    } catch (ExpiredException $e) {
        throw new Exception('JWT has expired - scan is too old');
    } catch (SignatureInvalidException $e) {
        throw new Exception('JWT signature validation failed - possible tampering');
    } catch (Exception $e) {
        throw new Exception('JWT validation failed: ' . $e->getMessage());
    }
}

/**
 * Example usage
 */
if (basename(__FILE__) == basename($_SERVER['SCRIPT_FILENAME'])) {
    // This code runs when the file is executed directly

    header('Content-Type: text/plain');

    // Get parameters from query string
    $jwt = $_GET['vkjwt'] ?? null;
    $status = $_GET['vkstatus'] ?? null;
    $uid = $_GET['vkuid'] ?? null;

    if ($jwt) {
        // JWT present - validate it
        try {
            $result = validateAuthentiChipJWT($jwt);
            $chipId = $result['chipId'];
            $uid = $result['uid'];

            echo "SUCCESS - Chip Verified\n";
            echo "========================\n";
            echo "Chip ID: $chipId\n";
            echo "UID: $uid\n\n";
            echo "This chip has been cryptographically verified.\n";
            echo "You can use this chip ID to:\n";
            echo "- Look up product information\n";
            echo "- Grant access to premium content\n";
            echo "- Record the scan in your database\n";
            echo "- Provide personalized experiences\n";

        } catch (Exception $e) {
            http_response_code(401);

            echo "ERROR - Validation Failed\n";
            echo "=========================\n";
            echo "Error: " . $e->getMessage() . "\n\n";
            echo "This could be:\n";
            echo "- An expired scan (older than 5 minutes)\n";
            echo "- A tampered/forged JWT\n";
            echo "- A network error fetching verification keys\n";
        }

    } elseif ($status && $uid) {
        // Unverified scan
        http_response_code(200); // Not an error, but unverified

        echo "UNVERIFIED SCAN\n";
        echo "===============\n";
        echo "Status: $status\n";
        echo "UID: $uid\n\n";

        if ($status === 'insecure') {
            echo "The verification API was unavailable at scan time.\n";
            echo "This scan cannot be cryptographically verified.\n";
        } elseif ($status === 'expired') {
            echo "The chip signature expired before verification.\n";
            echo "This may be a replay attack.\n";
        }

        echo "\nDo NOT grant access to sensitive features.\n";
        echo "You may use this to:\n";
        echo "- Display basic product information\n";
        echo "- Log the scan attempt\n";
        echo "- Show a 'verification unavailable' message\n";

    } else {
        // No authentication parameters
        http_response_code(400);

        echo "NO AUTHENTICATION\n";
        echo "=================\n";
        echo "No vkjwt, vkstatus, or vkuid parameters found.\n";
        echo "This URL was not accessed via AuthentiChip scan.\n";
    }
}

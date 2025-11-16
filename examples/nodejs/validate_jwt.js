/**
 * AuthentiChip JWT Validation for Node.js
 *
 * Validates JWT from the vkjwt query parameter and extracts the verified chip ID.
 */

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

/**
 * JWKS client for fetching public keys from auth.vivokey.com
 * Automatically caches keys for 6 hours
 */
const client = jwksClient({
    jwksUri: 'https://auth.vivokey.com/.well-known/jwks.json',
    cache: true,
    cacheMaxAge: 21600000, // 6 hours in milliseconds
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    timeout: 10000, // 10 seconds
});

/**
 * Get the signing key for JWT verification
 *
 * @param {Object} header - JWT header
 * @param {Function} callback - Callback(err, key)
 */
function getKey(header, callback) {
    client.getSigningKey(header.kid, (err, key) => {
        if (err) {
            return callback(err);
        }
        const signingKey = key.getPublicKey();
        callback(null, signingKey);
    });
}

/**
 * Validate an AuthentiChip JWT and extract the chip ID
 *
 * @param {string} token - The JWT token from vkjwt parameter
 * @returns {Promise<Object>} - Object with chipId (SHA-256 hash), uid (7-byte chip UID), and serial (optional item identifier)
 * @throws {Error} - If validation fails
 */
async function validateAuthentiChipJWT(token) {
    return new Promise((resolve, reject) => {
        if (!token) {
            return reject(new Error('JWT token is required'));
        }

        // Verify and decode the JWT
        jwt.verify(
            token,
            getKey,
            {
                algorithms: ['RS256'],
                issuer: 'auth.vivokey.com',
                clockTolerance: 10, // Allow 10 seconds clock skew
            },
            (err, decoded) => {
                if (err) {
                    if (err.name === 'TokenExpiredError') {
                        return reject(new Error('JWT has expired - scan is too old'));
                    } else if (err.name === 'JsonWebTokenError') {
                        return reject(new Error('JWT signature validation failed - possible tampering'));
                    } else {
                        return reject(new Error(`JWT validation failed: ${err.message}`));
                    }
                }

                // Extract chip ID from subject claim
                const chipId = decoded.sub;

                if (!chipId) {
                    return reject(new Error('Missing subject (chip ID) in JWT'));
                }

                // Validate chip ID format (SHA-256 hash - 64 hex characters)
                const sha256Regex = /^[0-9a-f]{64}$/i;
                if (!sha256Regex.test(chipId)) {
                    return reject(new Error('Invalid chip ID format - expected SHA-256 hash'));
                }

                // Validate product claim (must be 6 for AuthentiChip)
                if (!decoded.product || decoded.product !== 6) {
                    return reject(new Error('Invalid product claim - expected product=6 for AuthentiChip'));
                }

                // Validate audience claim exists
                if (!decoded.aud) {
                    return reject(new Error('Missing audience (aud) claim in JWT'));
                }

                // Extract UID and optional serial from client data claim
                let uid = null;
                let serial = null;
                if (decoded.cld) {
                    try {
                        const cldData = JSON.parse(decoded.cld);
                        uid = cldData.uid;
                        serial = cldData.serial || null;
                    } catch (e) {
                        return reject(new Error('Invalid client data (cld) claim - not valid JSON'));
                    }
                }
                if (!uid) {
                    return reject(new Error('Missing uid in client data (cld) claim'));
                }

                resolve({ chipId, uid, serial });
            }
        );
    });
}

/**
 * Example HTTP server for testing
 */
if (require.main === module) {
    const http = require('http');
    const url = require('url');

    const server = http.createServer(async (req, res) => {
        const queryObject = url.parse(req.url, true).query;
        const vkjwt = queryObject.vkjwt;
        const vkstatus = queryObject.vkstatus;
        const vkuid = queryObject.vkuid;

        res.setHeader('Content-Type', 'text/plain');

        if (vkjwt) {
            try {
                const { chipId, uid, serial } = await validateAuthentiChipJWT(vkjwt);

                res.statusCode = 200;
                res.end(`SUCCESS - Chip Verified
========================
Chip ID: ${chipId}
UID: ${uid}${serial ? `\nSerial: ${serial}` : ''}

This chip has been cryptographically verified.
You can use this chip ID to:
- Look up product information
- Grant access to premium content
- Record the scan in your database
- Provide personalized experiences
`);

            } catch (error) {
                res.statusCode = 401;
                res.end(`ERROR - Validation Failed
=========================
Error: ${error.message}

This could be:
- An expired scan (older than 5 minutes)
- A tampered/forged JWT
- A network error fetching verification keys
`);
            }

        } else if (vkstatus && vkuid) {
            res.statusCode = 200;
            res.end(`UNVERIFIED SCAN
===============
Status: ${vkstatus}
UID: ${vkuid}

${vkstatus === 'insecure'
    ? 'The verification API was unavailable at scan time.\nThis scan cannot be cryptographically verified.'
    : 'The chip signature expired before verification.\nThis may be a replay attack.'
}

Do NOT grant access to sensitive features.
You may use this to:
- Display basic product information
- Log the scan attempt
- Show a 'verification unavailable' message
`);

        } else {
            res.statusCode = 400;
            res.end(`NO AUTHENTICATION
=================
No vkjwt, vkstatus, or vkuid parameters found.
This URL was not accessed via AuthentiChip scan.

Test with:
  http://localhost:3000?vkjwt=<token>
  http://localhost:3000?vkuid=ABC123&vkstatus=insecure
`);
        }
    });

    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => {
        console.log(`AuthentiChip validation server running on port ${PORT}`);
        console.log(`\nTest with:`);
        console.log(`  http://localhost:${PORT}?vkjwt=<token>`);
        console.log(`  http://localhost:${PORT}?vkuid=ABC123&vkstatus=insecure`);
    });
}

module.exports = { validateAuthentiChipJWT };

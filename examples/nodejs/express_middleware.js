/**
 * Express.js Middleware for AuthentiChip JWT Validation
 *
 * Usage:
 *   const { authentiChipMiddleware } = require('./express_middleware');
 *
 *   // Apply to all routes
 *   app.use(authentiChipMiddleware());
 *
 *   // Apply to specific routes with options
 *   app.get('/product/:id',
 *       authentiChipMiddleware({ required: true }),
 *       (req, res) => {
 *           console.log('Chip ID:', req.chipId);
 *           console.log('Verified:', req.chipVerified);
 *       }
 *   );
 */

const { validateAuthentiChipJWT } = require('./validate_jwt');

/**
 * AuthentiChip validation middleware
 *
 * Adds the following properties to the request object:
 * - req.chipId: Verified chip ID (UUID) or null
 * - req.chipVerified: Boolean indicating if chip was verified
 * - req.chipStatus: 'verified', 'expired', 'invalid', 'insecure', 'error', or 'none'
 * - req.chipUid: Raw UID for unverified scans
 *
 * @param {Object} options - Configuration options
 * @param {boolean} options.required - If true, reject requests without valid JWT (default: false)
 * @param {Function} options.onVerified - Callback(req, chipId) called when chip is verified
 * @param {Function} options.onUnverified - Callback(req, uid, status) called for unverified scans
 * @returns {Function} Express middleware function
 */
function authentiChipMiddleware(options = {}) {
    const {
        required = false,
        onVerified = null,
        onUnverified = null,
    } = options;

    return async (req, res, next) => {
        const vkjwt = req.query.vkjwt;
        const vkstatus = req.query.vkstatus;
        const vkuid = req.query.vkuid;

        // Initialize request properties
        req.chipId = null;
        req.chipVerified = false;
        req.chipStatus = 'none';
        req.chipUid = null;

        // Attempt JWT validation if present
        if (vkjwt) {
            try {
                const chipId = await validateAuthentiChipJWT(vkjwt);

                req.chipId = chipId;
                req.chipVerified = true;
                req.chipStatus = 'verified';

                // Log successful verification
                console.log('[AuthentiChip] Verified:', {
                    chipId,
                    ip: req.ip,
                    userAgent: req.get('user-agent'),
                    timestamp: new Date().toISOString(),
                });

                // Call onVerified callback if provided
                if (onVerified) {
                    onVerified(req, chipId);
                }

                return next();

            } catch (error) {
                // Determine error type
                if (error.message.includes('expired')) {
                    req.chipStatus = 'expired';
                } else if (error.message.includes('signature')) {
                    req.chipStatus = 'invalid';
                } else {
                    req.chipStatus = 'error';
                }

                console.error('[AuthentiChip] Validation failed:', {
                    status: req.chipStatus,
                    error: error.message,
                    ip: req.ip,
                    timestamp: new Date().toISOString(),
                });

                if (required) {
                    return res.status(401).json({
                        error: 'Invalid chip authentication',
                        message: error.message,
                        status: req.chipStatus,
                    });
                }

                // Continue without verification
                return next();
            }
        }

        // Handle unverified scans with status parameter
        else if (vkstatus && vkuid) {
            req.chipUid = vkuid;
            req.chipStatus = vkstatus;
            req.chipVerified = false;

            console.log('[AuthentiChip] Unverified scan:', {
                uid: vkuid,
                status: vkstatus,
                ip: req.ip,
                timestamp: new Date().toISOString(),
            });

            // Call onUnverified callback if provided
            if (onUnverified) {
                onUnverified(req, vkuid, vkstatus);
            }

            if (required) {
                return res.status(401).json({
                    error: 'Unverified scan',
                    message: 'This chip could not be verified',
                    status: vkstatus,
                });
            }

            return next();
        }

        // No authentication parameters
        else {
            req.chipStatus = 'none';

            if (required) {
                return res.status(401).json({
                    error: 'Authentication required',
                    message: 'No chip authentication provided',
                });
            }

            return next();
        }
    };
}

/**
 * Example Express application
 */
if (require.main === module) {
    const express = require('express');
    const app = express();

    // Apply middleware to all routes
    app.use(authentiChipMiddleware({
        onVerified: (req, chipId) => {
            console.log('Custom handler - verified:', chipId);
        },
        onUnverified: (req, uid, status) => {
            console.log('Custom handler - unverified:', { uid, status });
        },
    }));

    // Example route - optional authentication
    app.get('/', (req, res) => {
        res.json({
            chipVerified: req.chipVerified,
            chipId: req.chipId,
            chipStatus: req.chipStatus,
            message: req.chipVerified
                ? `Welcome! Verified chip: ${req.chipId}`
                : 'No verified chip detected',
        });
    });

    // Example route - required authentication
    app.get('/protected',
        authentiChipMiddleware({ required: true }),
        (req, res) => {
            res.json({
                message: 'Access granted',
                chipId: req.chipId,
            });
        }
    );

    // Example product page
    app.get('/product/:id', (req, res) => {
        const product = {
            id: req.params.id,
            name: 'Example Product',
            verified: req.chipVerified,
        };

        if (req.chipVerified) {
            product.chipId = req.chipId;
            product.message = 'This is a verified authentic product';
        } else if (req.chipStatus === 'insecure' || req.chipStatus === 'expired') {
            product.message = 'Verification was unavailable - authenticity cannot be confirmed';
            product.uid = req.chipUid;
            product.status = req.chipStatus;
        } else {
            product.message = 'No chip scan detected';
        }

        res.json(product);
    });

    const PORT = process.env.PORT || 3001;
    app.listen(PORT, () => {
        console.log(`Express server running on port ${PORT}`);
        console.log(`\nTest with:`);
        console.log(`  http://localhost:${PORT}?vkjwt=<token>`);
        console.log(`  http://localhost:${PORT}?vkuid=ABC123&vkstatus=insecure`);
        console.log(`  http://localhost:${PORT}/protected?vkjwt=<token>`);
    });
}

module.exports = { authentiChipMiddleware };

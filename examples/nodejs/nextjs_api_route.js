/**
 * Next.js API Route for AuthentiChip JWT Validation
 *
 * Installation:
 * 1. Copy this file to: pages/api/authentichip/verify.js
 * 2. Install dependencies: npm install jsonwebtoken jwks-rsa
 * 3. Access via: /api/authentichip/verify?vkjwt=<token>
 *
 * Or use in getServerSideProps for page-level validation
 */

import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

/**
 * JWKS client for fetching public keys
 * Cached automatically by the library
 */
const client = jwksClient({
    jwksUri: 'https://auth.vivokey.com/.well-known/jwks.json',
    cache: true,
    cacheMaxAge: 21600000, // 6 hours
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    timeout: 10000,
});

/**
 * Get signing key from JWKS
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
 * Validate AuthentiChip JWT
 */
async function validateAuthentiChipJWT(token) {
    return new Promise((resolve, reject) => {
        if (!token) {
            return reject(new Error('JWT token is required'));
        }

        jwt.verify(
            token,
            getKey,
            {
                algorithms: ['RS256'],
                issuer: 'auth.vivokey.com',
                clockTolerance: 10,
            },
            (err, decoded) => {
                if (err) {
                    if (err.name === 'TokenExpiredError') {
                        return reject(new Error('JWT has expired'));
                    } else if (err.name === 'JsonWebTokenError') {
                        return reject(new Error('JWT signature validation failed'));
                    } else {
                        return reject(new Error(`JWT validation failed: ${err.message}`));
                    }
                }

                const chipId = decoded.sub;

                if (!chipId) {
                    return reject(new Error('Missing chip ID in JWT'));
                }

                resolve(chipId);
            }
        );
    });
}

/**
 * API Route Handler
 *
 * GET /api/authentichip/verify?vkjwt=<token>
 * GET /api/authentichip/verify?vkuid=<uid>&vkstatus=<status>
 */
export default async function handler(req, res) {
    // Only allow GET requests
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { vkjwt, vkstatus, vkuid } = req.query;

    // Handle JWT verification
    if (vkjwt) {
        try {
            const chipId = await validateAuthentiChipJWT(vkjwt);

            return res.status(200).json({
                verified: true,
                chipId,
                timestamp: new Date().toISOString(),
            });

        } catch (error) {
            console.error('[AuthentiChip] Validation failed:', error.message);

            return res.status(401).json({
                verified: false,
                error: error.message,
                timestamp: new Date().toISOString(),
            });
        }
    }

    // Handle unverified scans
    else if (vkstatus && vkuid) {
        console.log('[AuthentiChip] Unverified scan:', { vkuid, vkstatus });

        return res.status(200).json({
            verified: false,
            vkuid,
            vkstatus,
            message: vkstatus === 'insecure'
                ? 'Verification API was unavailable'
                : 'Chip signature expired',
            timestamp: new Date().toISOString(),
        });
    }

    // No authentication parameters
    else {
        return res.status(400).json({
            error: 'No authentication parameters provided',
            message: 'Expected vkjwt or vkstatus+vkuid query parameters',
        });
    }
}

/**
 * Example usage in getServerSideProps
 *
 * Copy this function to your Next.js page component:
 *
 * export async function getServerSideProps(context) {
 *     const { vkjwt, vkstatus, vkuid } = context.query;
 *
 *     let chipData = { verified: false };
 *
 *     if (vkjwt) {
 *         try {
 *             const chipId = await validateAuthentiChipJWT(vkjwt);
 *             chipData = { verified: true, chipId };
 *         } catch (error) {
 *             chipData = { verified: false, error: error.message };
 *         }
 *     } else if (vkstatus && vkuid) {
 *         chipData = { verified: false, vkstatus, vkuid };
 *     }
 *
 *     return {
 *         props: {
 *             chipData,
 *             productId: context.params.id,
 *         }
 *     };
 * }
 *
 * export default function ProductPage({ chipData, productId }) {
 *     return (
 *         <div>
 *             <h1>Product {productId}</h1>
 *             {chipData.verified ? (
 *                 <div className="verified">
 *                     <p>Verified Authentic</p>
 *                     <p>Chip ID: {chipData.chipId}</p>
 *                 </div>
 *             ) : (
 *                 <div className="unverified">
 *                     <p>Verification Unavailable</p>
 *                     {chipData.vkstatus && (
 *                         <p>Status: {chipData.vkstatus}</p>
 *                     )}
 *                 </div>
 *             )}
 *         </div>
 *     );
 * }
 */

/**
 * Example React component for client-side verification
 *
 * import { useEffect, useState } from 'react';
 * import { useRouter } from 'next/router';
 *
 * export default function VerifiedProductPage() {
 *     const router = useRouter();
 *     const [chipData, setChipData] = useState(null);
 *     const [loading, setLoading] = useState(true);
 *
 *     useEffect(() => {
 *         const { vkjwt, vkstatus, vkuid } = router.query;
 *
 *         if (vkjwt || (vkstatus && vkuid)) {
 *             // Call our API route
 *             const params = new URLSearchParams(router.query);
 *             fetch(`/api/authentichip/verify?${params}`)
 *                 .then(res => res.json())
 *                 .then(data => {
 *                     setChipData(data);
 *                     setLoading(false);
 *                 })
 *                 .catch(err => {
 *                     console.error('Verification failed:', err);
 *                     setLoading(false);
 *                 });
 *         } else {
 *             setLoading(false);
 *         }
 *     }, [router.query]);
 *
 *     if (loading) return <div>Verifying...</div>;
 *
 *     if (!chipData) return <div>No chip scan detected</div>;
 *
 *     if (chipData.verified) {
 *         return (
 *             <div>
 *                 <h1>Verified Authentic</h1>
 *                 <p>Chip ID: {chipData.chipId}</p>
 *             </div>
 *         );
 *     } else {
 *         return (
 *             <div>
 *                 <h1>Verification Unavailable</h1>
 *                 <p>Status: {chipData.vkstatus}</p>
 *             </div>
 *         );
 *     }
 * }
 */

export { validateAuthentiChipJWT };

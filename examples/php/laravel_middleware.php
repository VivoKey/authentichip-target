<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Laravel Middleware for AuthentiChip JWT Validation
 *
 * Installation:
 * 1. Copy this file to app/Http/Middleware/ValidateAuthentiChip.php
 * 2. Register in app/Http/Kernel.php:
 *    protected $middlewareAliases = [
 *        'authentichip' => \App\Http\Middleware\ValidateAuthentiChip::class,
 *    ];
 * 3. Apply to routes:
 *    Route::get('/product/{id}', [ProductController::class, 'show'])
 *        ->middleware('authentichip');
 *
 * Usage in controller:
 *    $chipId = $request->attributes->get('chip_id');
 *    $uid = $request->attributes->get('chip_uid');
 *    $isVerified = $request->attributes->get('chip_verified');
 *    $status = $request->attributes->get('chip_status');
 */
class ValidateAuthentiChip
{
    /**
     * Handle an incoming request
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $mode  'required' to reject unverified scans, 'optional' to allow
     * @return mixed
     */
    public function handle(Request $request, Closure $next, ?string $mode = 'optional')
    {
        $jwt = $request->query('vkjwt');
        $status = $request->query('vkstatus');
        $uid = $request->query('vkuid');

        // Attempt JWT validation if present
        if ($jwt) {
            try {
                $result = $this->validateJWT($jwt);
                $chipId = $result['chipId'];
                $chipUid = $result['uid'];

                // Store verified chip data in request attributes
                $request->attributes->set('chip_id', $chipId);
                $request->attributes->set('chip_uid', $chipUid);
                $request->attributes->set('chip_verified', true);
                $request->attributes->set('chip_status', 'verified');

                Log::info('AuthentiChip verified', [
                    'chip_id' => $chipId,
                    'uid' => $chipUid,
                    'ip' => $request->ip(),
                    'user_agent' => $request->userAgent(),
                ]);

                return $next($request);

            } catch (ExpiredException $e) {
                Log::warning('AuthentiChip JWT expired', [
                    'ip' => $request->ip(),
                    'error' => $e->getMessage(),
                ]);

                if ($mode === 'required') {
                    return response()->json([
                        'error' => 'Scan expired',
                        'message' => 'This scan is too old. Please scan again.',
                    ], 401);
                }

                // Continue with unverified flag
                $request->attributes->set('chip_verified', false);
                $request->attributes->set('chip_status', 'expired');

            } catch (SignatureInvalidException $e) {
                Log::error('AuthentiChip JWT signature invalid', [
                    'ip' => $request->ip(),
                    'error' => $e->getMessage(),
                ]);

                if ($mode === 'required') {
                    return response()->json([
                        'error' => 'Invalid chip',
                        'message' => 'This chip could not be verified.',
                    ], 401);
                }

                $request->attributes->set('chip_verified', false);
                $request->attributes->set('chip_status', 'invalid');

            } catch (\Exception $e) {
                Log::error('AuthentiChip JWT validation failed', [
                    'ip' => $request->ip(),
                    'error' => $e->getMessage(),
                ]);

                if ($mode === 'required') {
                    return response()->json([
                        'error' => 'Validation failed',
                        'message' => 'Unable to verify chip.',
                    ], 401);
                }

                $request->attributes->set('chip_verified', false);
                $request->attributes->set('chip_status', 'error');
            }
        }

        // Handle unverified scans with status parameter
        elseif ($status && $uid) {
            $request->attributes->set('chip_uid', $uid);
            $request->attributes->set('chip_verified', false);
            $request->attributes->set('chip_status', $status);

            Log::info('AuthentiChip unverified scan', [
                'uid' => $uid,
                'status' => $status,
                'ip' => $request->ip(),
            ]);

            if ($mode === 'required') {
                return response()->json([
                    'error' => 'Unverified scan',
                    'message' => 'This chip could not be verified.',
                ], 401);
            }
        }

        // No authentication parameters
        else {
            $request->attributes->set('chip_verified', false);
            $request->attributes->set('chip_status', 'none');

            if ($mode === 'required') {
                return response()->json([
                    'error' => 'Authentication required',
                    'message' => 'No chip authentication provided.',
                ], 401);
            }
        }

        return $next($request);
    }

    /**
     * Validate JWT and extract chip ID and UID
     *
     * @param string $jwt
     * @return array Associative array with 'chipId' and 'uid'
     * @throws \Exception
     */
    protected function validateJWT(string $jwt): array
    {
        // Fetch JWKS (cached for 6 hours)
        $jwks = Cache::remember('authentichip_jwks', 21600, function () {
            $response = Http::timeout(10)
                ->get('https://auth.vivokey.com/.well-known/jwks.json');

            if (!$response->successful()) {
                throw new \Exception('Unable to fetch JWKS');
            }

            return $response->json();
        });

        // Parse keys
        $keys = JWK::parseKeySet($jwks);

        // Decode and validate JWT
        $decoded = JWT::decode($jwt, $keys);

        // Verify issuer
        if (!isset($decoded->iss) || $decoded->iss !== 'auth.vivokey.com') {
            throw new \Exception('Invalid issuer');
        }

        // Extract chip ID
        if (!isset($decoded->sub) || empty($decoded->sub)) {
            throw new \Exception('Missing chip ID');
        }

        $chipId = $decoded->sub;

        // Validate chip ID format (SHA-256 hash - 64 hex characters)
        if (!preg_match('/^[0-9a-f]{64}$/i', $chipId)) {
            throw new \Exception('Invalid chip ID format - expected SHA-256 hash');
        }

        // Validate product claim (must be 6 for AuthentiChip)
        if (!isset($decoded->product) || $decoded->product !== 6) {
            throw new \Exception('Invalid product claim - expected product=6 for AuthentiChip');
        }

        // Validate audience claim exists
        if (!isset($decoded->aud) || empty($decoded->aud)) {
            throw new \Exception('Missing audience (aud) claim in JWT');
        }

        // Extract UID from client data claim
        if (!isset($decoded->cld) || empty($decoded->cld)) {
            throw new \Exception('Missing client data (cld) claim');
        }

        // Parse cld as JSON string
        $cldData = json_decode($decoded->cld);
        if ($cldData === null || !isset($cldData->uid) || empty($cldData->uid)) {
            throw new \Exception('Missing uid in client data (cld) claim');
        }

        $uid = $cldData->uid;

        return [
            'chipId' => $chipId,
            'uid' => $uid
        ];
    }
}

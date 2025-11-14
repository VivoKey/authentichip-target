"""
AuthentiChip JWT Validation for Python

Validates JWT from the vkjwt query parameter and extracts the verified chip ID.
"""

import jwt
import requests
import time
import re
from typing import Dict, Any
from functools import lru_cache

# JWKS URL for fetching public keys
JWKS_URL = 'https://auth.vivokey.com/.well-known/jwks.json'

# Cache duration in seconds (6 hours)
JWKS_CACHE_DURATION = 21600


class JWKSCache:
    """Simple in-memory cache for JWKS with expiration"""

    def __init__(self):
        self.jwks = None
        self.expiry = 0

    def get(self):
        if self.jwks is None or time.time() >= self.expiry:
            return None
        return self.jwks

    def set(self, jwks, duration=JWKS_CACHE_DURATION):
        self.jwks = jwks
        self.expiry = time.time() + duration


# Global JWKS cache
_jwks_cache = JWKSCache()


def fetch_jwks() -> Dict[str, Any]:
    """
    Fetch JWKS from auth.vivokey.com with caching

    Returns:
        dict: JWKS response

    Raises:
        Exception: If unable to fetch JWKS
    """
    # Check cache first
    cached = _jwks_cache.get()
    if cached is not None:
        return cached

    # Fetch fresh JWKS
    try:
        response = requests.get(JWKS_URL, timeout=10)
        response.raise_for_status()
        jwks = response.json()

        if 'keys' not in jwks:
            raise Exception('Invalid JWKS response format')

        # Cache the result
        _jwks_cache.set(jwks)

        return jwks

    except requests.RequestException as e:
        raise Exception(f'Unable to fetch JWKS: {str(e)}')


def get_signing_key(token: str) -> str:
    """
    Get the signing key for JWT verification

    Args:
        token: JWT token string

    Returns:
        str: PEM-formatted public key

    Raises:
        Exception: If key cannot be found
    """
    # Decode header without verification to get kid
    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:
        raise Exception(f'Invalid JWT format: {str(e)}')

    kid = header.get('kid')
    if not kid:
        raise Exception('No kid in JWT header')

    # Fetch JWKS
    jwks = fetch_jwks()

    # Find the matching key
    for key in jwks.get('keys', []):
        if key.get('kid') == kid:
            # Convert JWK to PEM format using PyJWT's built-in method
            try:
                from jwt.algorithms import RSAAlgorithm
                public_key = RSAAlgorithm.from_jwk(key)
                return public_key
            except Exception as e:
                raise Exception(f'Unable to parse signing key: {str(e)}')

    raise Exception(f'Signing key with kid {kid} not found in JWKS')


def validate_authentichip_jwt(token: str) -> str:
    """
    Validate an AuthentiChip JWT and extract the chip ID

    Args:
        token: The JWT token from vkjwt parameter

    Returns:
        str: The verified chip ID (UUID)

    Raises:
        Exception: If validation fails for any reason
    """
    if not token:
        raise Exception('JWT token is required')

    try:
        # Get the signing key
        signing_key = get_signing_key(token)

        # Decode and validate the JWT
        decoded = jwt.decode(
            token,
            signing_key,
            algorithms=['RS256'],
            issuer='auth.vivokey.com',
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_iss': True,
                'require': ['exp', 'iss', 'sub'],
            }
        )

        # Extract chip ID from subject claim
        chip_id = decoded.get('sub')

        if not chip_id:
            raise Exception('Missing subject (chip ID) in JWT')

        # Validate chip ID format (UUID)
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        if not re.match(uuid_pattern, chip_id, re.IGNORECASE):
            raise Exception('Invalid chip ID format')

        return chip_id

    except jwt.ExpiredSignatureError:
        raise Exception('JWT has expired - scan is too old')
    except jwt.InvalidSignatureError:
        raise Exception('JWT signature validation failed - possible tampering')
    except jwt.InvalidIssuerError:
        raise Exception('Invalid issuer - expected auth.vivokey.com')
    except jwt.DecodeError as e:
        raise Exception(f'JWT decode error: {str(e)}')
    except Exception as e:
        if 'JWT' in str(e) or 'token' in str(e).lower():
            raise
        raise Exception(f'JWT validation failed: {str(e)}')


def main():
    """Example HTTP server for testing"""
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from urllib.parse import urlparse, parse_qs

    class AuthentiChipHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Parse query parameters
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)

            vkjwt = params.get('vkjwt', [None])[0]
            vkstatus = params.get('vkstatus', [None])[0]
            vkuid = params.get('vkuid', [None])[0]

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()

            if vkjwt:
                try:
                    chip_id = validate_authentichip_jwt(vkjwt)

                    response = f"""SUCCESS - Chip Verified
========================
Chip ID: {chip_id}

This chip has been cryptographically verified.
You can use this chip ID to:
- Look up product information
- Grant access to premium content
- Record the scan in your database
- Provide personalized experiences
"""
                    self.wfile.write(response.encode())

                except Exception as e:
                    response = f"""ERROR - Validation Failed
=========================
Error: {str(e)}

This could be:
- An expired scan (older than 5 minutes)
- A tampered/forged JWT
- A network error fetching verification keys
"""
                    self.wfile.write(response.encode())

            elif vkstatus and vkuid:
                message = (
                    'The verification API was unavailable at scan time.\n'
                    'This scan cannot be cryptographically verified.'
                    if vkstatus == 'insecure'
                    else
                    'The chip signature expired before verification.\n'
                    'This may be a replay attack.'
                )

                response = f"""UNVERIFIED SCAN
===============
Status: {vkstatus}
UID: {vkuid}

{message}

Do NOT grant access to sensitive features.
You may use this to:
- Display basic product information
- Log the scan attempt
- Show a 'verification unavailable' message
"""
                self.wfile.write(response.encode())

            else:
                response = """NO AUTHENTICATION
=================
No vkjwt, vkstatus, or vkuid parameters found.
This URL was not accessed via AuthentiChip scan.

Test with:
  http://localhost:5000?vkjwt=<token>
  http://localhost:5000?vkuid=ABC123&vkstatus=insecure
"""
                self.wfile.write(response.encode())

        def log_message(self, format, *args):
            """Custom logging to reduce noise"""
            print(f"[{self.log_date_time_string()}] {format % args}")

    PORT = 5000
    server = HTTPServer(('', PORT), AuthentiChipHandler)
    print(f'AuthentiChip validation server running on port {PORT}')
    print(f'\nTest with:')
    print(f'  http://localhost:{PORT}?vkjwt=<token>')
    print(f'  http://localhost:{PORT}?vkuid=ABC123&vkstatus=insecure')
    server.serve_forever()


if __name__ == '__main__':
    main()

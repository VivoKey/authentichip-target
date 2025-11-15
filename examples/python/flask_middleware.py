"""
Flask Middleware and Decorators for AuthentiChip JWT Validation

Usage:
    from flask import Flask
    from flask_middleware import require_authentichip, authentichip_optional

    app = Flask(__name__)

    @app.route('/product/<id>')
    @authentichip_optional
    def product(id):
        if request.chip_verified:
            return f"Verified chip: {request.chip_id}"
        else:
            return "Unverified scan"

    @app.route('/protected')
    @require_authentichip
    def protected():
        return f"Access granted to chip: {request.chip_id}"
"""

from functools import wraps
from flask import request, jsonify, g
import logging
from validate_jwt import validate_authentichip_jwt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('authentichip')


def authentichip_optional(f):
    """
    Decorator that attempts to validate AuthentiChip JWT but continues
    regardless of validation result.

    Adds the following attributes to the request object:
    - request.chip_id: Verified chip ID (SHA-256 hash) or None
    - request.chip_uid: 7-byte chip UID or None
    - request.chip_verified: Boolean indicating if chip was verified
    - request.chip_status: 'verified', 'expired', 'invalid', 'insecure', 'error', or 'none'
    - request.chip_raw_uid: Raw UID for unverified scans

    Usage:
        @app.route('/product/<id>')
        @authentichip_optional
        def product(id):
            if request.chip_verified:
                return f"Verified: {request.chip_id}"
            return "Not verified"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        vkjwt = request.args.get('vkjwt')
        vkstatus = request.args.get('vkstatus')
        vkuid = request.args.get('vkuid')

        # Initialize request attributes
        request.chip_id = None
        request.chip_uid = None
        request.chip_verified = False
        request.chip_status = 'none'
        request.chip_raw_uid = None

        # Attempt JWT validation
        if vkjwt:
            try:
                result = validate_authentichip_jwt(vkjwt)

                request.chip_id = result['chipId']
                request.chip_uid = result['uid']
                request.chip_verified = True
                request.chip_status = 'verified'

                logger.info(
                    f'AuthentiChip verified: {result["chipId"]} (UID: {result["uid"]}) '
                    f'from {request.remote_addr}'
                )

            except Exception as e:
                error_msg = str(e).lower()

                if 'expired' in error_msg:
                    request.chip_status = 'expired'
                elif 'signature' in error_msg:
                    request.chip_status = 'invalid'
                else:
                    request.chip_status = 'error'

                logger.warning(
                    f'AuthentiChip validation failed: {e} '
                    f'from {request.remote_addr}'
                )

        # Handle unverified scans
        elif vkstatus and vkuid:
            request.chip_raw_uid = vkuid
            request.chip_status = vkstatus
            request.chip_verified = False

            logger.info(
                f'AuthentiChip unverified scan: '
                f'UID={vkuid}, status={vkstatus} '
                f'from {request.remote_addr}'
            )

        return f(*args, **kwargs)

    return decorated_function


def require_authentichip(f):
    """
    Decorator that requires valid AuthentiChip JWT authentication.
    Returns 401 if validation fails or no JWT is present.

    Adds the following attributes to the request object:
    - request.chip_id: Verified chip ID (SHA-256 hash)
    - request.chip_uid: 7-byte chip UID
    - request.chip_verified: Always True (or request aborted)
    - request.chip_status: Always 'verified' (or request aborted)

    Usage:
        @app.route('/protected')
        @require_authentichip
        def protected():
            return f"Access granted: {request.chip_id}"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        vkjwt = request.args.get('vkjwt')

        if not vkjwt:
            logger.warning(
                f'AuthentiChip required but not provided '
                f'from {request.remote_addr}'
            )
            return jsonify({
                'error': 'Authentication required',
                'message': 'No chip authentication provided'
            }), 401

        try:
            result = validate_authentichip_jwt(vkjwt)

            request.chip_id = result['chipId']
            request.chip_uid = result['uid']
            request.chip_verified = True
            request.chip_status = 'verified'

            logger.info(
                f'AuthentiChip verified: {result["chipId"]} (UID: {result["uid"]}) '
                f'from {request.remote_addr}'
            )

            return f(*args, **kwargs)

        except Exception as e:
            error_msg = str(e).lower()

            if 'expired' in error_msg:
                status = 'expired'
                message = 'This scan is too old. Please scan again.'
            elif 'signature' in error_msg:
                status = 'invalid'
                message = 'This chip could not be verified.'
            else:
                status = 'error'
                message = 'Unable to verify chip.'

            logger.error(
                f'AuthentiChip validation failed: {e} '
                f'from {request.remote_addr}'
            )

            return jsonify({
                'error': 'Invalid chip authentication',
                'message': message,
                'status': status
            }), 401

    return decorated_function


"""
Example Flask application
"""
if __name__ == '__main__':
    from flask import Flask

    app = Flask(__name__)

    @app.route('/')
    @authentichip_optional
    def index():
        return jsonify({
            'chip_verified': request.chip_verified,
            'chip_id': request.chip_id,
            'chip_uid': request.chip_uid,
            'chip_status': request.chip_status,
            'message': (
                f'Welcome! Verified chip: {request.chip_id} (UID: {request.chip_uid})'
                if request.chip_verified
                else 'No verified chip detected'
            )
        })

    @app.route('/product/<product_id>')
    @authentichip_optional
    def product(product_id):
        product_data = {
            'id': product_id,
            'name': 'Example Product',
            'verified': request.chip_verified
        }

        if request.chip_verified:
            product_data['chip_id'] = request.chip_id
            product_data['uid'] = request.chip_uid
            product_data['message'] = 'This is a verified authentic product'
        elif request.chip_status in ('insecure', 'expired'):
            product_data['message'] = 'Verification was unavailable'
            product_data['uid'] = request.chip_raw_uid
            product_data['status'] = request.chip_status
        else:
            product_data['message'] = 'No chip scan detected'

        return jsonify(product_data)

    @app.route('/protected')
    @require_authentichip
    def protected():
        return jsonify({
            'message': 'Access granted',
            'chip_id': request.chip_id,
            'uid': request.chip_uid
        })

    @app.route('/optional')
    @authentichip_optional
    def optional():
        if request.chip_verified:
            return jsonify({
                'level': 'premium',
                'chip_id': request.chip_id,
                'uid': request.chip_uid,
                'content': 'Full access granted'
            })
        else:
            return jsonify({
                'level': 'basic',
                'content': 'Limited access'
            })

    PORT = 5001
    print(f'Flask server running on port {PORT}')
    print(f'\nTest with:')
    print(f'  http://localhost:{PORT}?vkjwt=<token>')
    print(f'  http://localhost:{PORT}/product/123?vkuid=ABC&vkstatus=insecure')
    print(f'  http://localhost:{PORT}/protected?vkjwt=<token>')
    app.run(debug=True, port=PORT)

"""
Django Middleware for AuthentiChip JWT Validation

Installation:
    1. Copy this file to your Django project (e.g., myapp/middleware/authentichip.py)
    2. Add to MIDDLEWARE in settings.py:
        MIDDLEWARE = [
            # ... other middleware
            'myapp.middleware.authentichip.AuthentiChipMiddleware',
        ]

Usage in views:
    from django.http import JsonResponse

    def product_view(request, product_id):
        chip_id = getattr(request, 'chip_id', None)
        chip_verified = getattr(request, 'chip_verified', False)

        if chip_verified:
            return JsonResponse({
                'verified': True,
                'chip_id': chip_id
            })
        else:
            return JsonResponse({
                'verified': False
            })

Decorator for required authentication:
    from myapp.middleware.authentichip import require_authentichip

    @require_authentichip
    def protected_view(request):
        # Only executes if chip is verified
        return JsonResponse({
            'chip_id': request.chip_id
        })
"""

import logging
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from functools import wraps

# Import the validation function from validate_jwt.py
# Make sure validate_jwt.py is in the same directory or in PYTHONPATH
try:
    from .validate_jwt import validate_authentichip_jwt
except ImportError:
    from validate_jwt import validate_authentichip_jwt

logger = logging.getLogger('authentichip')


class AuthentiChipMiddleware(MiddlewareMixin):
    """
    Django middleware for AuthentiChip JWT validation

    Adds the following attributes to the request object:
    - request.chip_id: Verified chip ID (UUID) or None
    - request.chip_verified: Boolean indicating if chip was verified
    - request.chip_status: 'verified', 'expired', 'invalid', 'insecure', 'error', or 'none'
    - request.chip_uid: Raw UID for unverified scans
    """

    def process_request(self, request):
        """Process incoming request and validate AuthentiChip parameters"""

        vkjwt = request.GET.get('vkjwt')
        vkstatus = request.GET.get('vkstatus')
        vkuid = request.GET.get('vkuid')

        # Initialize request attributes
        request.chip_id = None
        request.chip_verified = False
        request.chip_status = 'none'
        request.chip_uid = None

        # Attempt JWT validation
        if vkjwt:
            try:
                chip_id = validate_authentichip_jwt(vkjwt)

                request.chip_id = chip_id
                request.chip_verified = True
                request.chip_status = 'verified'

                logger.info(
                    f'AuthentiChip verified: {chip_id} '
                    f'from {self._get_client_ip(request)}'
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
                    f'from {self._get_client_ip(request)}'
                )

        # Handle unverified scans
        elif vkstatus and vkuid:
            request.chip_uid = vkuid
            request.chip_status = vkstatus
            request.chip_verified = False

            logger.info(
                f'AuthentiChip unverified scan: '
                f'UID={vkuid}, status={vkstatus} '
                f'from {self._get_client_ip(request)}'
            )

        # No return value means continue processing
        return None

    def _get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


def require_authentichip(view_func):
    """
    Decorator that requires valid AuthentiChip JWT authentication.
    Returns 401 if validation fails or no JWT is present.

    Usage:
        @require_authentichip
        def protected_view(request):
            return JsonResponse({'chip_id': request.chip_id})
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # Check if middleware has run
        if not hasattr(request, 'chip_verified'):
            logger.error('AuthentiChipMiddleware not configured')
            return JsonResponse({
                'error': 'Server configuration error'
            }, status=500)

        # Check if chip is verified
        if not request.chip_verified:
            chip_status = getattr(request, 'chip_status', 'none')

            if chip_status == 'expired':
                message = 'This scan is too old. Please scan again.'
            elif chip_status == 'invalid':
                message = 'This chip could not be verified.'
            elif chip_status == 'none':
                message = 'No chip authentication provided.'
            else:
                message = 'Unable to verify chip.'

            logger.warning(
                f'AuthentiChip required but not verified '
                f'(status: {chip_status}) '
                f'from {request.META.get("REMOTE_ADDR")}'
            )

            return JsonResponse({
                'error': 'Authentication required',
                'message': message,
                'status': chip_status
            }, status=401)

        # Chip is verified, proceed with view
        return view_func(request, *args, **kwargs)

    return wrapper


"""
Example Django view usage
"""
if __name__ == '__main__':
    # Example views showing usage patterns

    def example_optional_view(request):
        """Example view with optional authentication"""
        chip_id = getattr(request, 'chip_id', None)
        chip_verified = getattr(request, 'chip_verified', False)
        chip_status = getattr(request, 'chip_status', 'none')

        return JsonResponse({
            'chip_verified': chip_verified,
            'chip_id': chip_id,
            'chip_status': chip_status,
            'message': (
                f'Welcome! Verified chip: {chip_id}'
                if chip_verified
                else 'No verified chip detected'
            )
        })

    @require_authentichip
    def example_required_view(request):
        """Example view with required authentication"""
        return JsonResponse({
            'message': 'Access granted',
            'chip_id': request.chip_id
        })

    def example_product_view(request, product_id):
        """Example product view"""
        chip_verified = getattr(request, 'chip_verified', False)
        chip_id = getattr(request, 'chip_id', None)
        chip_status = getattr(request, 'chip_status', 'none')
        chip_uid = getattr(request, 'chip_uid', None)

        product_data = {
            'id': product_id,
            'name': 'Example Product',
            'verified': chip_verified
        }

        if chip_verified:
            product_data['chip_id'] = chip_id
            product_data['message'] = 'This is a verified authentic product'
        elif chip_status in ('insecure', 'expired'):
            product_data['message'] = 'Verification was unavailable'
            product_data['uid'] = chip_uid
            product_data['status'] = chip_status
        else:
            product_data['message'] = 'No chip scan detected'

        return JsonResponse(product_data)

    print("""
Django Middleware Example

Add to settings.py:
    MIDDLEWARE = [
        # ... other middleware
        'myapp.middleware.authentichip.AuthentiChipMiddleware',
    ]

Use in views:
    from django.http import JsonResponse
    from myapp.middleware.authentichip import require_authentichip

    def product_view(request, product_id):
        if request.chip_verified:
            return JsonResponse({'chip_id': request.chip_id})
        return JsonResponse({'verified': False})

    @require_authentichip
    def protected_view(request):
        return JsonResponse({'chip_id': request.chip_id})
""")

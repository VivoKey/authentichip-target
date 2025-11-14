# Python - AuthentiChip JWT Validation

Examples for validating AuthentiChip JWTs in Python applications.

## Requirements

- Python 3.7 or higher (3.9+ recommended)
- pip for package management

## Dependencies

Install the required packages:

```bash
pip install pyjwt cryptography requests
```

Or using the requirements file:

```bash
pip install -r requirements.txt
```

## Files

- `validate_jwt.py` - Standalone JWT validation function
- `flask_middleware.py` - Flask decorator and middleware
- `django_middleware.py` - Django middleware
- `requirements.txt` - Python dependencies

## Quick Start

### Standalone Usage

```python
from validate_jwt import validate_authentichip_jwt

# From Flask request
@app.route('/product/<id>')
def product(id):
    vkjwt = request.args.get('vkjwt')
    vkstatus = request.args.get('vkstatus')
    vkuid = request.args.get('vkuid')

    if vkjwt:
        try:
            chip_id = validate_authentichip_jwt(vkjwt)
            return jsonify({
                'verified': True,
                'chip_id': chip_id,
                'product_id': id
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 401

    elif vkstatus and vkuid:
        return jsonify({
            'verified': False,
            'vkstatus': vkstatus,
            'vkuid': vkuid
        })

    else:
        return jsonify({'error': 'No authentication parameters'}), 400
```

### Flask Decorator

```python
from flask import Flask, request, jsonify
from flask_middleware import require_authentichip, authentichip_optional

app = Flask(__name__)

# Optional authentication - continues even if not verified
@app.route('/product/<id>')
@authentichip_optional
def product(id):
    # Access via request.chip_id, request.chip_verified, etc.
    if request.chip_verified:
        return jsonify({
            'verified': True,
            'chip_id': request.chip_id,
            'product': 'Full details here'
        })
    else:
        return jsonify({
            'verified': False,
            'product': 'Limited info'
        })

# Required authentication - returns 401 if not verified
@app.route('/protected')
@require_authentichip
def protected():
    # Only executes if chip is verified
    return jsonify({
        'message': 'Access granted',
        'chip_id': request.chip_id
    })
```

### Django Middleware

```python
# settings.py
MIDDLEWARE = [
    # ... other middleware
    'path.to.django_middleware.AuthentiChipMiddleware',
]

# views.py
from django.http import JsonResponse

def product_view(request, product_id):
    chip_id = getattr(request, 'chip_id', None)
    chip_verified = getattr(request, 'chip_verified', False)

    if chip_verified:
        return JsonResponse({
            'verified': True,
            'chip_id': chip_id,
            'product': 'Full details'
        })
    else:
        return JsonResponse({
            'verified': False,
            'product': 'Limited info'
        })
```

## Security Notes

- Always validate JWT signatures - never trust without verification
- Use HTTPS in production to prevent token interception
- Cache JWKS responses (6 hours default) to reduce API calls
- Use environment variables for sensitive configuration
- Log validation failures for security monitoring
- Consider rate limiting on your endpoints

## Testing

Run the standalone example server:

```bash
python validate_jwt.py
```

Then access:
```
http://localhost:5000?vkjwt=<token>
http://localhost:5000?vkuid=ABC123&vkstatus=insecure
```

## Common Issues

**"Unable to fetch JWKS" error**: Network connectivity issue or auth.vivokey.com is unreachable. Check firewall and internet connection.

**"Token has expired" error**: JWT has exceeded its 5-minute validity window. Normal for old scans.

**"Signature verification failed" error**: JWT signature validation failed. Could indicate tampering or incorrect public key.

**Import errors**: Ensure all dependencies are installed: `pip install -r requirements.txt`

## Environment Variables

You can configure caching behavior using environment variables:

```python
# Optional: Customize JWKS cache duration (in seconds)
AUTHENTICHIP_JWKS_CACHE_DURATION=21600  # 6 hours (default)
```

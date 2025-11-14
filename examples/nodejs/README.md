# Node.js - AuthentiChip JWT Validation

Examples for validating AuthentiChip JWTs in Node.js applications.

## Requirements

- Node.js 14 or higher (16+ recommended)
- npm or yarn

## Dependencies

Install the required packages:

```bash
npm install jsonwebtoken jwks-rsa node-fetch
```

## Files

- `validate_jwt.js` - Standalone JWT validation function
- `express_middleware.js` - Express.js middleware
- `nextjs_api_route.js` - Next.js API route handler
- `package.json` - Dependencies and scripts

## Quick Start

### Standalone Usage

```javascript
const { validateAuthentiChipJWT } = require('./validate_jwt');

// From HTTP request (Express example)
app.get('/product/:id', async (req, res) => {
    const jwt = req.query.vkjwt;
    const status = req.query.vkstatus;
    const uid = req.query.vkuid;

    if (jwt) {
        try {
            const chipId = await validateAuthentiChipJWT(jwt);
            console.log('Verified chip:', chipId);

            // Use chipId to look up product, grant access, etc.
            res.json({ verified: true, chipId });

        } catch (error) {
            console.error('Validation failed:', error.message);
            res.status(401).json({ error: error.message });
        }
    } else if (status && uid) {
        // Unverified scan
        console.log('Unverified scan:', { uid, status });
        res.json({ verified: false, uid, status });
    } else {
        res.status(400).json({ error: 'No authentication parameters' });
    }
});
```

### Express Middleware

```javascript
const express = require('express');
const { authentiChipMiddleware } = require('./express_middleware');

const app = express();

// Apply to all routes
app.use(authentiChipMiddleware());

// Or apply to specific routes
app.get('/product/:id',
    authentiChipMiddleware({ required: true }),
    (req, res) => {
        if (req.chipVerified) {
            res.json({
                verified: true,
                chipId: req.chipId,
                product: { /* ... */ }
            });
        } else {
            res.json({
                verified: false,
                status: req.chipStatus
            });
        }
    }
);

app.listen(3000);
```

### Next.js API Route

```javascript
// pages/api/verify.js
import { validateAuthentiChipJWT } from './validate_jwt';

export default async function handler(req, res) {
    const { vkjwt, vkstatus, vkuid } = req.query;

    if (vkjwt) {
        try {
            const chipId = await validateAuthentiChipJWT(vkjwt);
            res.status(200).json({ verified: true, chipId });
        } catch (error) {
            res.status(401).json({ error: error.message });
        }
    } else if (vkstatus && vkuid) {
        res.status(200).json({ verified: false, vkstatus, vkuid });
    } else {
        res.status(400).json({ error: 'No authentication parameters' });
    }
}
```

### Next.js Page Component

```javascript
// pages/product/[id].js
import { validateAuthentiChipJWT } from '../../lib/validate_jwt';

export async function getServerSideProps(context) {
    const { vkjwt, vkstatus, vkuid } = context.query;

    let chipData = { verified: false };

    if (vkjwt) {
        try {
            const chipId = await validateAuthentiChipJWT(vkjwt);
            chipData = { verified: true, chipId };
        } catch (error) {
            chipData = { verified: false, error: error.message };
        }
    } else if (vkstatus && vkuid) {
        chipData = { verified: false, vkstatus, vkuid };
    }

    return {
        props: { chipData }
    };
}

export default function Product({ chipData }) {
    if (chipData.verified) {
        return <div>Verified chip: {chipData.chipId}</div>;
    } else {
        return <div>Unverified scan</div>;
    }
}
```

## Security Notes

- Always validate JWT signatures - never trust without verification
- Use HTTPS in production to prevent token interception
- Cache JWKS responses to reduce API calls and improve performance
- Set appropriate timeout values for HTTP requests
- Log validation failures for security monitoring
- Use environment variables for configuration (never hardcode)

## Testing

Run the test server:

```bash
node validate_jwt.js
```

Then access:
```
http://localhost:3000?vkjwt=<token>
http://localhost:3000?vkuid=ABC123&vkstatus=insecure
```

## Common Issues

**"Unable to fetch JWKS" error**: Network connectivity issue or auth.vivokey.com is unreachable. Check firewall and internet connection.

**"Token expired" error**: JWT has exceeded its 5-minute validity window. Normal for old scans.

**"Invalid signature" error**: JWT signature verification failed. Could indicate tampering or incorrect public key.

**JWKS caching**: The middleware caches JWKS for 6 hours by default. Adjust the TTL if you need more frequent updates.

# Go - AuthentiChip JWT Validation

Examples for validating AuthentiChip JWTs in Go applications.

## Requirements

- Go 1.19 or higher (1.21+ recommended)

## Dependencies

Install the required packages:

```bash
go get github.com/golang-jwt/jwt/v5
go get github.com/MicahParks/keyfunc/v2
```

Or using the go.mod file:

```bash
go mod download
```

## Files

- `validate_jwt.go` - Standalone JWT validation package
- `middleware.go` - Standard library HTTP middleware
- `gin_middleware.go` - gin-gonic framework middleware
- `go.mod` - Go module definition

## Quick Start

### Standalone Usage

```go
package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/yourusername/authentichip"
)

func productHandler(w http.ResponseWriter, r *http.Request) {
    vkjwt := r.URL.Query().Get("vkjwt")
    vkstatus := r.URL.Query().Get("vkstatus")
    vkuid := r.URL.Query().Get("vkuid")

    if vkjwt != "" {
        chipID, err := authentichip.ValidateJWT(vkjwt)
        if err != nil {
            http.Error(w, err.Error(), http.StatusUnauthorized)
            return
        }

        fmt.Fprintf(w, "Verified chip: %s", chipID)
    } else if vkstatus != "" && vkuid != "" {
        fmt.Fprintf(w, "Unverified scan - UID: %s, Status: %s", vkuid, vkstatus)
    } else {
        http.Error(w, "No authentication parameters", http.StatusBadRequest)
    }
}

func main() {
    http.HandleFunc("/product", productHandler)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### HTTP Middleware

```go
package main

import (
    "log"
    "net/http"

    "github.com/yourusername/authentichip"
)

func protectedHandler(w http.ResponseWriter, r *http.Request) {
    // Get chip ID from context (set by middleware)
    chipID := r.Context().Value(authentichip.ChipIDKey).(string)
    w.Write([]byte("Access granted to chip: " + chipID))
}

func main() {
    // Apply middleware to all routes
    http.Handle("/", authentichip.Middleware(http.HandlerFunc(indexHandler)))

    // Apply with required authentication
    http.Handle("/protected",
        authentichip.MiddlewareRequired(http.HandlerFunc(protectedHandler)))

    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Gin Framework

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/yourusername/authentichip"
)

func main() {
    r := gin.Default()

    // Optional authentication
    r.GET("/product/:id", authentichip.GinMiddleware(), func(c *gin.Context) {
        chipID, verified := c.Get("chip_id")

        if verified {
            c.JSON(200, gin.H{
                "verified": true,
                "chip_id":  chipID,
            })
        } else {
            c.JSON(200, gin.H{
                "verified": false,
            })
        }
    })

    // Required authentication
    protected := r.Group("/protected")
    protected.Use(authentichip.GinMiddlewareRequired())
    {
        protected.GET("/data", func(c *gin.Context) {
            chipID, _ := c.Get("chip_id")
            c.JSON(200, gin.H{
                "chip_id": chipID,
                "message": "Access granted",
            })
        })
    }

    r.Run(":8080")
}
```

## Security Notes

- Always validate JWT signatures - never trust without verification
- Use HTTPS in production to prevent token interception
- JWKS responses are cached automatically for 6 hours
- Set appropriate timeout values for HTTP requests
- Log validation failures for security monitoring
- Use context values to pass chip ID between middleware and handlers

## Testing

Run the example server:

```bash
go run validate_jwt.go
```

Or build and run:

```bash
go build -o authentichip-server
./authentichip-server
```

Then access:
```
http://localhost:8080?vkjwt=<token>
http://localhost:8080?vkuid=ABC123&vkstatus=insecure
```

## Common Issues

**"Unable to fetch JWKS" error**: Network connectivity issue or auth.vivokey.com is unreachable. Check firewall and internet connection.

**"Token is expired" error**: JWT has exceeded its 5-minute validity window. Normal for old scans.

**"Signature is invalid" error**: JWT signature verification failed. Could indicate tampering or incorrect public key.

**Import errors**: Run `go mod download` to fetch dependencies.

## Performance

The JWT validation library automatically caches JWKS responses and parsed keys for optimal performance. Typical validation takes < 1ms after initial JWKS fetch.

## Environment Variables

You can configure behavior using environment variables:

```bash
# Optional: Customize JWKS cache duration (in seconds)
AUTHENTICHIP_JWKS_CACHE_DURATION=21600  # 6 hours (default)
```

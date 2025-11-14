// Package authentichip provides JWT validation for AuthentiChip scans
package authentichip

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// JWKSURL is the URL for fetching public keys
	JWKSURL = "https://auth.vivokey.com/.well-known/jwks.json"

	// Issuer is the expected JWT issuer
	Issuer = "auth.vivokey.com"

	// JWKSRefreshInterval is how often to refresh JWKS (6 hours)
	JWKSRefreshInterval = 6 * time.Hour
)

var (
	// ErrNoToken indicates no JWT was provided
	ErrNoToken = errors.New("no JWT token provided")

	// ErrInvalidFormat indicates JWT is malformed
	ErrInvalidFormat = errors.New("invalid JWT format")

	// ErrExpired indicates JWT has expired
	ErrExpired = errors.New("JWT has expired - scan is too old")

	// ErrInvalidSignature indicates signature verification failed
	ErrInvalidSignature = errors.New("JWT signature validation failed - possible tampering")

	// ErrInvalidIssuer indicates issuer doesn't match expected value
	ErrInvalidIssuer = errors.New("invalid issuer - expected auth.vivokey.com")

	// ErrMissingChipID indicates no subject claim in JWT
	ErrMissingChipID = errors.New("missing subject (chip ID) in JWT")

	// ErrInvalidChipID indicates chip ID format is invalid
	ErrInvalidChipID = errors.New("invalid chip ID format")

	// jwks is the global JWKS client (initialized on first use)
	jwks *keyfunc.JWKS

	// uuidRegex validates chip ID format
	uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// getJWKS returns the JWKS client, initializing it if necessary
func getJWKS() (*keyfunc.JWKS, error) {
	if jwks != nil {
		return jwks, nil
	}

	// Create JWKS client with automatic refresh
	options := keyfunc.Options{
		RefreshInterval:   JWKSRefreshInterval,
		RefreshRateLimit:  time.Minute,
		RefreshTimeout:    10 * time.Second,
		RefreshUnknownKID: true,
	}

	var err error
	jwks, err = keyfunc.Get(JWKSURL, options)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	return jwks, nil
}

// ValidateJWT validates an AuthentiChip JWT and returns the chip ID
func ValidateJWT(tokenString string) (string, error) {
	if tokenString == "" {
		return "", ErrNoToken
	}

	// Get JWKS
	jwks, err := getJWKS()
	if err != nil {
		return "", err
	}

	// Parse and validate JWT
	token, err := jwt.Parse(tokenString, jwks.Keyfunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		// Map specific error types
		if errors.Is(err, jwt.ErrTokenExpired) {
			return "", ErrExpired
		}
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return "", ErrInvalidSignature
		}
		return "", fmt.Errorf("JWT validation failed: %w", err)
	}

	if !token.Valid {
		return "", ErrInvalidFormat
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", ErrInvalidFormat
	}

	// Verify issuer
	issuer, ok := claims["iss"].(string)
	if !ok || issuer != Issuer {
		return "", ErrInvalidIssuer
	}

	// Extract chip ID from subject
	chipID, ok := claims["sub"].(string)
	if !ok || chipID == "" {
		return "", ErrMissingChipID
	}

	// Validate chip ID format (UUID)
	if !uuidRegex.MatchString(chipID) {
		return "", ErrInvalidChipID
	}

	return chipID, nil
}

// Example HTTP server for testing
func main() {
	// This is in a separate example file in production
	// See example_server.go
}

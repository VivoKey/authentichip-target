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

	// ErrMissingAudience indicates no audience claim in JWT
	ErrMissingAudience = errors.New("missing audience (aud) in JWT")

	// ErrInvalidProduct indicates product type is not 6
	ErrInvalidProduct = errors.New("invalid product type - expected 6 (AuthentiChip)")

	// ErrMissingUID indicates no UID in client data
	ErrMissingUID = errors.New("missing UID in client data (cld)")

	// jwks is the global JWKS client (initialized on first use)
	jwks *keyfunc.JWKS

	// sha256Regex validates chip ID format (SHA-256 hash)
	sha256Regex = regexp.MustCompile(`^[0-9a-f]{64}$`)
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

// ValidationResult contains the validated chip information
type ValidationResult struct {
	ChipID string // SHA-256 hash from sub claim
	UID    string // Chip UID from cld.uid
}

// ValidateJWT validates an AuthentiChip JWT and returns the chip ID and UID
func ValidateJWT(tokenString string) (*ValidationResult, error) {
	if tokenString == "" {
		return nil, ErrNoToken
	}

	// Get JWKS
	jwks, err := getJWKS()
	if err != nil {
		return nil, err
	}

	// Parse and validate JWT
	token, err := jwt.Parse(tokenString, jwks.Keyfunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		// Map specific error types
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpired
		}
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, ErrInvalidSignature
		}
		return nil, fmt.Errorf("JWT validation failed: %w", err)
	}

	if !token.Valid {
		return nil, ErrInvalidFormat
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidFormat
	}

	// Verify issuer
	issuer, ok := claims["iss"].(string)
	if !ok || issuer != Issuer {
		return nil, ErrInvalidIssuer
	}

	// Verify audience exists
	_, ok = claims["aud"].(string)
	if !ok {
		return nil, ErrMissingAudience
	}

	// Verify product type is 6
	prd, ok := claims["prd"].(float64)
	if !ok || int(prd) != 6 {
		return nil, ErrInvalidProduct
	}

	// Extract chip ID from subject
	chipID, ok := claims["sub"].(string)
	if !ok || chipID == "" {
		return nil, ErrMissingChipID
	}

	// Validate chip ID format (SHA-256 hash)
	if !sha256Regex.MatchString(chipID) {
		return nil, ErrInvalidChipID
	}

	// Extract UID from client data
	cld, ok := claims["cld"].(map[string]interface{})
	if !ok {
		return nil, ErrMissingUID
	}

	uid, ok := cld["uid"].(string)
	if !ok || uid == "" {
		return nil, ErrMissingUID
	}

	return &ValidationResult{
		ChipID: chipID,
		UID:    uid,
	}, nil
}

// Example HTTP server for testing
func main() {
	// This is in a separate example file in production
	// See example_server.go
}

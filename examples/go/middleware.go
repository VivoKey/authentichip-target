package authentichip

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
)

type contextKey string

const (
	// ChipIDKey is the context key for the verified chip ID
	ChipIDKey contextKey = "chip_id"

	// ChipVerifiedKey is the context key for verification status
	ChipVerifiedKey contextKey = "chip_verified"

	// ChipStatusKey is the context key for the chip status
	ChipStatusKey contextKey = "chip_status"

	// ChipUIDKey is the context key for chip UID (verified or unverified)
	ChipUIDKey contextKey = "chip_uid"
)

// ChipStatus represents the verification status
type ChipStatus string

const (
	StatusVerified ChipStatus = "verified"
	StatusExpired  ChipStatus = "expired"
	StatusInvalid  ChipStatus = "invalid"
	StatusInsecure ChipStatus = "insecure"
	StatusError    ChipStatus = "error"
	StatusNone     ChipStatus = "none"
)

// ErrorResponse is the JSON error response structure
type ErrorResponse struct {
	Error   string     `json:"error"`
	Message string     `json:"message"`
	Status  ChipStatus `json:"status,omitempty"`
}

// Middleware validates AuthentiChip JWT but continues regardless of result
// Use this for optional authentication
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		vkjwt := query.Get("vkjwt")
		vkstatus := query.Get("vkstatus")
		vkuid := query.Get("vkuid")

		ctx := r.Context()
		ctx = context.WithValue(ctx, ChipVerifiedKey, false)
		ctx = context.WithValue(ctx, ChipStatusKey, StatusNone)

		// Attempt JWT validation
		if vkjwt != "" {
			result, err := ValidateJWT(vkjwt)
			if err == nil {
				// Success
				ctx = context.WithValue(ctx, ChipIDKey, result.ChipID)
				ctx = context.WithValue(ctx, ChipUIDKey, result.UID)
				ctx = context.WithValue(ctx, ChipVerifiedKey, true)
				ctx = context.WithValue(ctx, ChipStatusKey, StatusVerified)

				log.Printf("[AuthentiChip] Verified: ChipID=%s UID=%s from %s", result.ChipID, result.UID, r.RemoteAddr)
			} else {
				// Validation failed - determine status
				var status ChipStatus
				switch err {
				case ErrExpired:
					status = StatusExpired
				case ErrInvalidSignature:
					status = StatusInvalid
				default:
					status = StatusError
				}

				ctx = context.WithValue(ctx, ChipStatusKey, status)
				log.Printf("[AuthentiChip] Validation failed: %v from %s", err, r.RemoteAddr)
			}
		} else if vkstatus != "" && vkuid != "" {
			// Unverified scan
			ctx = context.WithValue(ctx, ChipUIDKey, vkuid)
			ctx = context.WithValue(ctx, ChipStatusKey, ChipStatus(vkstatus))
			ctx = context.WithValue(ctx, ChipVerifiedKey, false)

			log.Printf("[AuthentiChip] Unverified scan: UID=%s, status=%s from %s",
				vkuid, vkstatus, r.RemoteAddr)
		}

		// Continue with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// MiddlewareRequired validates AuthentiChip JWT and requires valid authentication
// Returns 401 if validation fails or no JWT is present
func MiddlewareRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		vkjwt := query.Get("vkjwt")

		if vkjwt == "" {
			log.Printf("[AuthentiChip] Required but not provided from %s", r.RemoteAddr)
			sendErrorJSON(w, http.StatusUnauthorized, ErrorResponse{
				Error:   "Authentication required",
				Message: "No chip authentication provided",
				Status:  StatusNone,
			})
			return
		}

		result, err := ValidateJWT(vkjwt)
		if err != nil {
			var errResp ErrorResponse
			switch err {
			case ErrExpired:
				errResp = ErrorResponse{
					Error:   "Invalid chip authentication",
					Message: "This scan is too old. Please scan again.",
					Status:  StatusExpired,
				}
			case ErrInvalidSignature:
				errResp = ErrorResponse{
					Error:   "Invalid chip authentication",
					Message: "This chip could not be verified.",
					Status:  StatusInvalid,
				}
			default:
				errResp = ErrorResponse{
					Error:   "Invalid chip authentication",
					Message: "Unable to verify chip.",
					Status:  StatusError,
				}
			}

			log.Printf("[AuthentiChip] Validation failed: %v from %s", err, r.RemoteAddr)
			sendErrorJSON(w, http.StatusUnauthorized, errResp)
			return
		}

		// Add chip info to context
		ctx := r.Context()
		ctx = context.WithValue(ctx, ChipIDKey, result.ChipID)
		ctx = context.WithValue(ctx, ChipUIDKey, result.UID)
		ctx = context.WithValue(ctx, ChipVerifiedKey, true)
		ctx = context.WithValue(ctx, ChipStatusKey, StatusVerified)

		log.Printf("[AuthentiChip] Verified: ChipID=%s UID=%s from %s", result.ChipID, result.UID, r.RemoteAddr)

		// Continue with authenticated request
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sendErrorJSON sends a JSON error response
func sendErrorJSON(w http.ResponseWriter, statusCode int, errResp ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errResp)
}

// GetChipID retrieves the chip ID from the request context
func GetChipID(r *http.Request) (string, bool) {
	chipID, ok := r.Context().Value(ChipIDKey).(string)
	return chipID, ok
}

// IsChipVerified checks if the chip was verified
func IsChipVerified(r *http.Request) bool {
	verified, ok := r.Context().Value(ChipVerifiedKey).(bool)
	return ok && verified
}

// GetChipStatus retrieves the chip status from the request context
func GetChipStatus(r *http.Request) ChipStatus {
	status, ok := r.Context().Value(ChipStatusKey).(ChipStatus)
	if !ok {
		return StatusNone
	}
	return status
}

// GetChipUID retrieves the chip UID from the request context (verified or unverified)
func GetChipUID(r *http.Request) (string, bool) {
	uid, ok := r.Context().Value(ChipUIDKey).(string)
	return uid, ok
}

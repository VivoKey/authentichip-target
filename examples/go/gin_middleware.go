package authentichip

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GinMiddleware validates AuthentiChip JWT but continues regardless of result
// Use this for optional authentication with gin-gonic framework
//
// Usage:
//
//	r.GET("/product/:id", GinMiddleware(), func(c *gin.Context) {
//	    chipID, exists := c.Get("chip_id")
//	    if exists {
//	        c.JSON(200, gin.H{"verified": true, "chip_id": chipID})
//	    } else {
//	        c.JSON(200, gin.H{"verified": false})
//	    }
//	})
func GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		vkjwt := c.Query("vkjwt")
		vkstatus := c.Query("vkstatus")
		vkuid := c.Query("vkuid")

		// Set defaults
		c.Set("chip_verified", false)
		c.Set("chip_status", string(StatusNone))

		// Attempt JWT validation
		if vkjwt != "" {
			result, err := ValidateJWT(vkjwt)
			if err == nil {
				// Success
				c.Set("chip_id", result.ChipID)
				c.Set("chip_uid", result.UID)
				c.Set("chip_verified", true)
				c.Set("chip_status", string(StatusVerified))

				log.Printf("[AuthentiChip] Verified: ChipID=%s UID=%s from %s", result.ChipID, result.UID, c.ClientIP())
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

				c.Set("chip_status", string(status))
				log.Printf("[AuthentiChip] Validation failed: %v from %s", err, c.ClientIP())
			}
		} else if vkstatus != "" && vkuid != "" {
			// Unverified scan
			c.Set("chip_uid", vkuid)
			c.Set("chip_status", vkstatus)
			c.Set("chip_verified", false)

			log.Printf("[AuthentiChip] Unverified scan: UID=%s, status=%s from %s",
				vkuid, vkstatus, c.ClientIP())
		}

		c.Next()
	}
}

// GinMiddlewareRequired validates AuthentiChip JWT and requires valid authentication
// Returns 401 if validation fails or no JWT is present
//
// Usage:
//
//	protected := r.Group("/protected")
//	protected.Use(GinMiddlewareRequired())
//	{
//	    protected.GET("/data", func(c *gin.Context) {
//	        chipID, _ := c.Get("chip_id")
//	        c.JSON(200, gin.H{"chip_id": chipID})
//	    })
//	}
func GinMiddlewareRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		vkjwt := c.Query("vkjwt")

		if vkjwt == "" {
			log.Printf("[AuthentiChip] Required but not provided from %s", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication required",
				"message": "No chip authentication provided",
				"status":  string(StatusNone),
			})
			c.Abort()
			return
		}

		result, err := ValidateJWT(vkjwt)
		if err != nil {
			var errResp gin.H
			switch err {
			case ErrExpired:
				errResp = gin.H{
					"error":   "Invalid chip authentication",
					"message": "This scan is too old. Please scan again.",
					"status":  string(StatusExpired),
				}
			case ErrInvalidSignature:
				errResp = gin.H{
					"error":   "Invalid chip authentication",
					"message": "This chip could not be verified.",
					"status":  string(StatusInvalid),
				}
			default:
				errResp = gin.H{
					"error":   "Invalid chip authentication",
					"message": "Unable to verify chip.",
					"status":  string(StatusError),
				}
			}

			log.Printf("[AuthentiChip] Validation failed: %v from %s", err, c.ClientIP())
			c.JSON(http.StatusUnauthorized, errResp)
			c.Abort()
			return
		}

		// Add chip info to context
		c.Set("chip_id", result.ChipID)
		c.Set("chip_uid", result.UID)
		c.Set("chip_verified", true)
		c.Set("chip_status", string(StatusVerified))

		log.Printf("[AuthentiChip] Verified: ChipID=%s UID=%s from %s", result.ChipID, result.UID, c.ClientIP())

		c.Next()
	}
}

// Example gin application
func ExampleGinApp() {
	r := gin.Default()

	// Optional authentication
	r.GET("/", GinMiddleware(), func(c *gin.Context) {
		chipVerified, _ := c.Get("chip_verified")
		chipID, _ := c.Get("chip_id")
		chipStatus, _ := c.Get("chip_status")

		c.JSON(200, gin.H{
			"chip_verified": chipVerified,
			"chip_id":       chipID,
			"chip_status":   chipStatus,
			"message": func() string {
				if chipVerified.(bool) {
					return "Welcome! Verified chip: " + chipID.(string)
				}
				return "No verified chip detected"
			}(),
		})
	})

	// Product endpoint with optional authentication
	r.GET("/product/:id", GinMiddleware(), func(c *gin.Context) {
		productID := c.Param("id")
		chipVerified, _ := c.Get("chip_verified")
		chipID, _ := c.Get("chip_id")
		chipStatus, _ := c.Get("chip_status")

		product := gin.H{
			"id":       productID,
			"name":     "Example Product",
			"verified": chipVerified,
		}

		if chipVerified.(bool) {
			product["chip_id"] = chipID
			product["message"] = "This is a verified authentic product"
		} else if chipStatus.(string) == string(StatusInsecure) || chipStatus.(string) == string(StatusExpired) {
			product["message"] = "Verification was unavailable"
			if uid, exists := c.Get("chip_uid"); exists {
				product["uid"] = uid
			}
			product["status"] = chipStatus
		} else {
			product["message"] = "No chip scan detected"
		}

		c.JSON(200, product)
	})

	// Protected routes requiring authentication
	protected := r.Group("/protected")
	protected.Use(GinMiddlewareRequired())
	{
		protected.GET("/data", func(c *gin.Context) {
			chipID, _ := c.Get("chip_id")
			c.JSON(200, gin.H{
				"message": "Access granted",
				"chip_id": chipID,
			})
		})

		protected.GET("/profile", func(c *gin.Context) {
			chipID, _ := c.Get("chip_id")
			c.JSON(200, gin.H{
				"chip_id": chipID,
				"profile": "User profile data",
			})
		})
	}

	// Optional routes
	optional := r.Group("/optional")
	optional.Use(GinMiddleware())
	{
		optional.GET("/content", func(c *gin.Context) {
			chipVerified, _ := c.Get("chip_verified")

			if chipVerified.(bool) {
				chipID, _ := c.Get("chip_id")
				c.JSON(200, gin.H{
					"level":   "premium",
					"chip_id": chipID,
					"content": "Full access granted",
				})
			} else {
				c.JSON(200, gin.H{
					"level":   "basic",
					"content": "Limited access",
				})
			}
		})
	}

	log.Println("Gin server running on :8080")
	log.Println("\nTest with:")
	log.Println("  http://localhost:8080?vkjwt=<token>")
	log.Println("  http://localhost:8080/product/123?vkuid=ABC&vkstatus=insecure")
	log.Println("  http://localhost:8080/protected/data?vkjwt=<token>")

	r.Run(":8080")
}

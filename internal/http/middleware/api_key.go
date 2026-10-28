package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"

	"threat-exchange/internal/controller"

	"github.com/gin-gonic/gin"
)

const apiKeyID = "api_key_id"

func APIKeyAuth(keys []string) gin.HandlerFunc {
	hashes := make([][32]byte, len(keys))
	for i, key := range keys {
		hashes[i] = sha256.Sum256([]byte(key))
	}
	return func(c *gin.Context) {
		values := c.Request.Header.Values("X-API-Key")
		if len(values) != 1 || values[0] == "" {
			controller.WriteError(c, http.StatusUnauthorized, "invalid or missing API key", "")
			return
		}
		candidate := sha256.Sum256([]byte(values[0]))
		match := 0
		for _, hash := range hashes {
			match |= subtle.ConstantTimeCompare(candidate[:], hash[:])
		}
		if match != 1 {
			controller.WriteError(c, http.StatusUnauthorized, "invalid or missing API key", "")
			return
		}
		c.Set(apiKeyID, candidate)
		c.Next()
	}
}

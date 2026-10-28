package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"threat-exchange/internal/controller"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func RequestLog(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var token [16]byte
		if _, err := rand.Read(token[:]); err != nil {
			controller.WriteError(c, http.StatusInternalServerError, "internal server error", "")
			return
		}
		id := hex.EncodeToString(token[:])
		c.Set("request_id", id)
		c.Header("X-Request-ID", id)
		started := time.Now()
		c.Next()
		logger.Info("HTTP request", zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path), zap.Int("status", c.Writer.Status()),
			zap.Duration("duration", time.Since(started)), zap.String("request_id", id))
	}
}

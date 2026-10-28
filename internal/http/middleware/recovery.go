package middleware

import (
	"net/http"

	"threat-exchange/internal/controller"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func Recovery(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if recover() != nil {
				logger.Error("request panicked", zap.String("request_id", c.GetString("request_id")), zap.Stack("stack"))
				controller.WriteError(c, http.StatusInternalServerError, "internal server error", "")
			}
		}()
		c.Next()
	}
}

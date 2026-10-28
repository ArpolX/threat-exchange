package middleware

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"

	"threat-exchange/internal/controller"

	"github.com/gin-gonic/gin"
)

const MaxBodyBytes = 64 << 10

func JSONBody() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodPost && c.Request.Method != http.MethodPut {
			c.Next()
			return
		}
		mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
		if err != nil || mediaType != "application/json" {
			controller.WriteError(c, http.StatusUnsupportedMediaType, "Content-Type must be application/json", "")
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, MaxBodyBytes))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				controller.WriteError(c, http.StatusRequestEntityTooLarge, "request body exceeds 64 KiB", "")
			} else {
				controller.WriteError(c, http.StatusBadRequest, "cannot read request body", "")
			}
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(data))
		c.Request.ContentLength = int64(len(data))
		c.Next()
	}
}

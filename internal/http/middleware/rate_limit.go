package middleware

import (
	"net/http"
	"strconv"
	"time"

	"threat-exchange/internal/controller"

	"github.com/gin-gonic/gin"
)

func (l *Limiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		key, ok := c.Get(apiKeyID)
		hash, valid := key.([32]byte)
		if !ok || !valid {
			controller.WriteError(c, http.StatusUnauthorized, "invalid or missing API key", "")
			return
		}
		now := l.now()
		l.mu.Lock()
		current := l.windows[hash]
		if !now.Before(current.resetsAt) {
			current = window{resetsAt: now.Add(l.interval)}
		}
		allowed := current.count < l.limit
		if allowed {
			current.count++
		}
		l.windows[hash] = current
		remaining := l.limit - current.count
		l.mu.Unlock()

		reset := current.resetsAt.Unix()
		if current.resetsAt.Nanosecond() != 0 {
			reset++
		}
		c.Header("X-RateLimit-Limit", strconv.Itoa(l.limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(reset, 10))
		if !allowed {
			retry := int64(current.resetsAt.Sub(now) / time.Second)
			if current.resetsAt.Sub(now)%time.Second != 0 {
				retry++
			}
			if retry < 1 {
				retry = 1
			}
			c.Header("Retry-After", strconv.FormatInt(retry, 10))
			controller.WriteError(c, http.StatusTooManyRequests, "rate limit exceeded", "")
			return
		}
		c.Next()
	}
}

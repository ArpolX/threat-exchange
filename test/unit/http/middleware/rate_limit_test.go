package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"threat-exchange/internal/http/middleware"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func limiterRouter(t *testing.T, limiter *middleware.Limiter) *gin.Engine {
	t.Helper()
	router := gin.New()
	router.Use(middleware.APIKeyAuth([]string{"first-key", "second-key"}), limiter.Middleware())
	router.GET("/info", func(c *gin.Context) { c.Status(http.StatusOK) })
	return router
}

func hit(router http.Handler, key string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/info", nil)
	if key != "" {
		request.Header.Set("X-API-Key", key)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestLimiterIsolatesKeysAndResetsAtBoundary(t *testing.T) {
	now := time.Unix(1700000000, 0)
	limiter, err := middleware.NewLimiter(2, time.Minute, func() time.Time { return now })
	require.NoError(t, err)
	router := limiterRouter(t, limiter)
	first := hit(router, "first-key")
	require.Equal(t, 200, first.Code)
	require.Equal(t, "1", first.Header().Get("X-RateLimit-Remaining"))
	require.Equal(t, "1700000060", first.Header().Get("X-RateLimit-Reset"))
	require.Equal(t, 200, hit(router, "first-key").Code)
	denied := hit(router, "first-key")
	require.Equal(t, 429, denied.Code)
	require.Equal(t, "0", denied.Header().Get("X-RateLimit-Remaining"))
	require.Equal(t, "60", denied.Header().Get("Retry-After"))
	require.Equal(t, 200, hit(router, "second-key").Code)
	now = now.Add(time.Minute)
	require.Equal(t, 200, hit(router, "first-key").Code)
	require.Equal(t, 200, hit(router, "first-key").Code)
	require.Equal(t, 429, hit(router, "first-key").Code)
	require.Equal(t, 200, hit(router, "second-key").Code)
}

func TestUnauthorizedRequestsDoNotConsumeQuota(t *testing.T) {
	limiter, err := middleware.NewLimiter(1, time.Minute, time.Now)
	require.NoError(t, err)
	router := limiterRouter(t, limiter)
	for _, key := range []string{"", "wrong", "first-key,second-key"} {
		require.Equal(t, 401, hit(router, key).Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/info", nil)
	request.Header.Add("X-API-Key", "first-key")
	request.Header.Add("X-API-Key", "second-key")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	require.Equal(t, 401, recorder.Code)
	require.Equal(t, 200, hit(router, "first-key").Code)
	require.Equal(t, 429, hit(router, "first-key").Code)
	require.Equal(t, 200, hit(router, "second-key").Code)
}

func TestLimiterEnforcesQuotaUnderConcurrentRequests(t *testing.T) {
	limiter, err := middleware.NewLimiter(10, time.Minute, time.Now)
	require.NoError(t, err)
	router := limiterRouter(t, limiter)
	var allowed, limited atomic.Int32
	var group sync.WaitGroup
	for range 100 {
		group.Go(func() {
			switch hit(router, "first-key").Code {
			case 200:
				allowed.Add(1)
			case 429:
				limited.Add(1)
			}
		})
	}
	group.Wait()
	require.EqualValues(t, 10, allowed.Load())
	require.EqualValues(t, 90, limited.Load())
}

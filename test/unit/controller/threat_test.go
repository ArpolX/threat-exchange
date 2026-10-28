package controller_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"threat-exchange/api"
	"threat-exchange/internal/apperror"
	"threat-exchange/internal/controller"
	"threat-exchange/internal/domain"
	"threat-exchange/internal/http/handlers"
	"threat-exchange/internal/http/middleware"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const hash = "d41d8cd98f00b204e9800998ecf8427e"
const key = "controller-development-key"

type serviceStub struct {
	create func(context.Context, string, domain.ThreatInput) (*domain.Threat, error)
	get    func(context.Context, string) (*domain.Threat, error)
	update func(context.Context, string, domain.ThreatInput) (*domain.Threat, error)
}

func (s *serviceStub) Create(ctx context.Context, md5 string, input domain.ThreatInput) (*domain.Threat, error) {
	return s.create(ctx, md5, input)
}
func (s *serviceStub) Get(ctx context.Context, md5 string) (*domain.Threat, error) {
	return s.get(ctx, md5)
}
func (s *serviceStub) Update(ctx context.Context, md5 string, input domain.ThreatInput) (*domain.Threat, error) {
	return s.update(ctx, md5, input)
}

func routerFor(t *testing.T, svc controller.Service) http.Handler {
	t.Helper()
	limiter, err := middleware.NewLimiter(1000, time.Minute, time.Now)
	require.NoError(t, err)
	log := zap.NewNop()
	ctrl := controller.New(svc, log)
	router, err := handlers.NewRouter(ctrl, log, middleware.APIKeyAuth([]string{key}), limiter.Middleware())
	require.NoError(t, err)
	return router
}

func request(router http.Handler, method, path, body, apiKey, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func TestCreateMapsDTOAndReturnsLocation(t *testing.T) {
	t.Parallel()
	sha := strings.Repeat("ab", 32)
	timestamp := time.Now().UTC()
	svc := &serviceStub{create: func(_ context.Context, md5 string, input domain.ThreatInput) (*domain.Threat, error) {
		require.Equal(t, hash, md5)
		require.Equal(t, domain.CategoryTrojan, input.Category)
		require.Equal(t, domain.SeverityHigh, input.Severity)
		require.Equal(t, sha, *input.SHA256)
		require.Equal(t, "analysis", input.Source)
		return &domain.Threat{MD5: md5, ThreatInput: input, CreatedAt: timestamp, UpdatedAt: timestamp}, nil
	}}
	body := `{"md5":"` + hash + `","name":"Trojan.Example","category":"trojan","severity":"high","source":"analysis","sha256":"` + sha + `"}`
	result := request(routerFor(t, svc), http.MethodPost, "/info", body, key, "application/json; charset=utf-8")
	require.Equal(t, 201, result.Code, result.Body.String())
	require.Equal(t, "/info/"+hash, result.Header().Get("Location"))
	require.NotEmpty(t, result.Header().Get("X-Request-ID"))
	require.Equal(t, "999", result.Header().Get("X-RateLimit-Remaining"))
	var response api.ThreatResponse
	require.NoError(t, json.Unmarshal(result.Body.Bytes(), &response))
	require.Equal(t, hash, response.Md5)
	require.Equal(t, timestamp, *response.CreatedAt)
	require.Equal(t, timestamp, *response.UpdatedAt)
}

func TestInvalidHTTPRequestsNeverReachService(t *testing.T) {
	t.Parallel()
	router := routerFor(t, &serviceStub{})
	valid := `{"md5":"` + hash + `","name":"Threat"}`
	for _, tc := range []struct {
		name, method, path, body, contentType string
		status                                int
	}{
		{"malformed", "POST", "/info", `{`, "application/json", 400},
		{"multiple values", "POST", "/info", valid + valid, "application/json", 400},
		{"null body", "POST", "/info", `null`, "application/json", 400},
		{"missing name", "POST", "/info", `{"md5":"` + hash + `"}`, "application/json", 400},
		{"blank name", "POST", "/info", `{"md5":"` + hash + `","name":"   "}`, "application/json", 400},
		{"invalid md5", "GET", "/info/not-a-hash", "", "", 400},
		{"bad sha256", "POST", "/info", `{"md5":"` + hash + `","name":"Threat","sha256":"bad"}`, "application/json", 400},
		{"enum", "POST", "/info", `{"md5":"` + hash + `","name":"Threat","severity":"urgent"}`, "application/json", 400},
		{"unknown field", "POST", "/info", `{"md5":"` + hash + `","name":"Threat","extra":true}`, "application/json", 400},
		{"server timestamp", "POST", "/info", `{"md5":"` + hash + `","name":"Threat","created_at":"2026-01-01T00:00:00Z"}`, "application/json", 400},
		{"nonnullable source", "POST", "/info", `{"md5":"` + hash + `","name":"Threat","source":null}`, "application/json", 400},
		{"case-sensitive field", "POST", "/info", `{"MD5":"` + hash + `","name":"Threat"}`, "application/json", 400},
		{"long name", "POST", "/info", `{"md5":"` + hash + `","name":"` + strings.Repeat("a", 256) + `"}`, "application/json", 400},
		{"wrong media type", "POST", "/info", valid, "text/plain", 415},
		{"no media type", "POST", "/info", valid, "", 415},
		{"large body", "POST", "/info", strings.Repeat(" ", middleware.MaxBodyBytes+1), "application/json", 413},
		{"md5 immutable", "PUT", "/info/" + hash, valid, "application/json", 400},
		{"unknown route", "GET", "/missing", "", "", 404},
		{"no readiness route", "GET", "/ready", "", "", 404},
		{"no health route", "GET", "/health", "", "", 404},
		{"unsupported method", "DELETE", "/info/" + hash, "", "", 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := request(router, tc.method, tc.path, tc.body, key, tc.contentType)
			require.Equal(t, tc.status, result.Code, result.Body.String())
			require.Contains(t, result.Header().Get("Content-Type"), "application/json")
			var response api.ErrorResponse
			require.NoError(t, json.Unmarshal(result.Body.Bytes(), &response))
			require.NotEmpty(t, response.Message)
		})
	}
}

func TestExpectedErrorsAndInternalErrorAreMapped(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err    error
		status int
	}{
		{apperror.ErrNotFound, 404}, {apperror.ErrAlreadyExists, 409},
		{apperror.ErrInvalidInput, 400}, {errors.New("private database details"), 500},
	} {
		svc := &serviceStub{get: func(context.Context, string) (*domain.Threat, error) { return nil, tc.err }}
		result := request(routerFor(t, svc), "GET", "/info/"+hash, "", key, "")
		require.Equal(t, tc.status, result.Code, result.Body.String())
		require.NotContains(t, result.Body.String(), "private database details")
	}
}

func TestAuthentication(t *testing.T) {
	t.Parallel()
	router := routerFor(t, &serviceStub{})
	for _, token := range []string{"", "wrong"} {
		require.Equal(t, 401, request(router, "GET", "/info/"+hash, "", token, "").Code)
	}
}

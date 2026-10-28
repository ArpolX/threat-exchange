//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"threat-exchange/api"
	"threat-exchange/internal/apperror"
	"threat-exchange/internal/controller"
	"threat-exchange/internal/domain"
	"threat-exchange/internal/http/handlers"
	"threat-exchange/internal/http/middleware"
	"threat-exchange/internal/infrastructure"
	"threat-exchange/internal/repository/postgres"
	"threat-exchange/internal/service"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestDatabaseTimeoutCancelsBlockedRequestsWithoutLateWrites(t *testing.T) {
	pool, _ := database(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	const queryTimeout = 200 * time.Millisecond
	schema := pool.Config().ConnConfig.RuntimeParams["search_path"]
	applicationName := schema + "_timeout"
	dsn, err := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	require.NoError(t, err)
	params := dsn.Query()
	params.Set("search_path", schema)
	params.Set("application_name", applicationName)
	params.Set("pool_max_conns", "1")
	dsn.RawQuery = params.Encode()
	limitedPool, err := infrastructure.ConnectPostgres(ctx, dsn.String(), queryTimeout)
	require.NoError(t, err)
	t.Cleanup(limitedPool.Close)
	var statementTimeout string
	require.NoError(t, limitedPool.QueryRow(ctx, "SHOW statement_timeout").Scan(&statementTimeout))
	require.Equal(t, "200ms", statementTimeout)

	repository := postgres.New(limitedPool, queryTimeout)
	svc := service.New(repository)
	original, err := svc.Create(ctx, md5, domain.ThreatInput{Name: "Original"})
	require.NoError(t, err)
	log := zap.NewNop()
	limiter, err := middleware.NewLimiter(100, time.Minute, time.Now)
	require.NoError(t, err)
	router, err := handlers.NewRouter(controller.New(svc, log), log,
		middleware.APIKeyAuth([]string{apiKey}), limiter.Middleware())
	require.NoError(t, err)
	server := httptest.NewUnstartedServer(router)
	server.Config.WriteTimeout = 2 * time.Second
	server.Start()
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 2 * time.Second

	call := func(t *testing.T, method, path, body string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, server.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("X-API-Key", apiKey)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		started := time.Now()
		response, err := client.Do(req)
		require.NoError(t, err)
		defer func() { require.NoError(t, response.Body.Close()) }()
		payload, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Less(t, time.Since(started), time.Second)
		require.Equal(t, http.StatusInternalServerError, response.StatusCode, string(payload))
		require.Contains(t, response.Header.Get("Content-Type"), "application/json")
		var result api.ErrorResponse
		require.NoError(t, json.Unmarshal(payload, &result))
		require.Equal(t, "internal server error", result.Message)
		require.Nil(t, result.Details)
	}

	lock, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = lock.Rollback(context.Background()) }()
	_, err = lock.Exec(ctx, "LOCK TABLE threats IN ACCESS EXCLUSIVE MODE")
	require.NoError(t, err)
	newMD5 := strings.Repeat("0", 32)
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/info", `{"md5":"` + newMD5 + `","name":"Late insert"}`},
		{"GET", "/info/" + md5, ""},
		{"PUT", "/info/" + md5, `{"name":"Late update"}`},
	} {
		t.Run(tc.method, func(t *testing.T) {
			call(t, tc.method, tc.path, tc.body)
			require.Eventually(t, func() bool {
				var active int
				err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
                    WHERE application_name = $1 AND state = 'active'`, applicationName).Scan(&active)
				return err == nil && active == 0
			}, time.Second, 10*time.Millisecond, "SQL must stop while the table is still locked")
		})
	}
	require.NoError(t, lock.Rollback(ctx))

	unchanged, err := repository.Get(ctx, md5)
	require.NoError(t, err)
	require.Equal(t, original, unchanged)
	_, err = repository.Get(ctx, newMD5)
	require.ErrorIs(t, err, apperror.ErrNotFound)
	updated, err := svc.Update(ctx, md5, domain.ThreatInput{Name: "After unlock"})
	require.NoError(t, err)
	require.Equal(t, "After unlock", updated.Name)

	t.Run("pool acquisition", func(t *testing.T) {
		conn, err := limitedPool.Acquire(ctx)
		require.NoError(t, err)
		defer conn.Release()
		call(t, "GET", "/info/"+md5, "")
	})
}

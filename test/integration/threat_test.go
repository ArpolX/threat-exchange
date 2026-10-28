//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"threat-exchange/api"
	"threat-exchange/internal/apperror"
	"threat-exchange/internal/controller"
	"threat-exchange/internal/domain"
	"threat-exchange/internal/http/handlers"
	"threat-exchange/internal/http/middleware"
	"threat-exchange/internal/repository/postgres"
	"threat-exchange/internal/service"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const md5 = "d41d8cd98f00b204e9800998ecf8427e"
const apiKey = "integration-development-key"

func database(t *testing.T) (*pgxpool.Pool, *goose.Provider) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	require.NotEmpty(t, dsn, "set TEST_DATABASE_URL to a local test PostgreSQL database")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(admin.Close)
	var random [12]byte
	_, err = rand.Read(random[:])
	require.NoError(t, err)
	schema := "test_threats_" + hex.EncodeToString(random[:])
	identifier := pgx.Identifier{schema}.Sanitize()
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+identifier)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE")
		if err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*cfg.ConnConfig)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	provider, err := goose.NewProvider(goose.DialectPostgres, db, os.DirFS("../../migrations"))
	require.NoError(t, err)
	_, err = provider.Up(ctx)
	require.NoError(t, err)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool, provider
}

func TestHTTPFlowWithPostgresAndOpenAPIResponses(t *testing.T) {
	pool, _ := database(t)
	limiter, err := middleware.NewLimiter(100, time.Minute, time.Now)
	require.NoError(t, err)
	log := zap.NewNop()
	ctrl := controller.New(service.New(postgres.New(pool)), log)
	router, err := handlers.NewRouter(ctrl, log, middleware.APIKeyAuth([]string{apiKey}), limiter.Middleware())
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	spec, err := api.LoadSpecification()
	require.NoError(t, err)
	contract, err := gorillamux.NewRouter(spec)
	require.NoError(t, err)

	call := func(method, path, body string, status int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), method, server.URL+path, bytes.NewBufferString(body))
		require.NoError(t, err)
		req.Header.Set("X-API-Key", apiKey)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := server.Client().Do(req)
		require.NoError(t, err)
		defer func() { require.NoError(t, resp.Body.Close()) }()
		payload, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, status, resp.StatusCode, string(payload))
		route, params, err := contract.FindRoute(req)
		require.NoError(t, err)
		validation := &openapi3filter.ResponseValidationInput{
			RequestValidationInput: &openapi3filter.RequestValidationInput{Request: req, Route: route, PathParams: params},
			Status:                 resp.StatusCode, Header: resp.Header,
			Options: &openapi3filter.Options{IncludeResponseStatus: true},
		}
		require.NoError(t, openapi3filter.ValidateResponse(context.Background(), validation.SetBodyBytes(payload)))
		return payload
	}
	sha := strings.Repeat("AB", 32)
	body := `{"md5":"` + strings.ToUpper(md5) + `","name":" Trojan.Example ","description":"Observed malware","severity":"high","category":"trojan","source":"Lab","sha256":"` + sha + `"}`
	var created api.ThreatResponse
	require.NoError(t, json.Unmarshal(call("POST", "/info", body, 201), &created))
	require.Equal(t, md5, created.Md5)
	require.Equal(t, "Trojan.Example", created.Name)
	require.Equal(t, strings.ToLower(sha), *created.Sha256)
	call("POST", "/info", body, 409)
	var fetched api.ThreatResponse
	require.NoError(t, json.Unmarshal(call("GET", "/info/"+strings.ToUpper(md5), "", 200), &fetched))
	require.Equal(t, created, fetched)
	var updated api.ThreatResponse
	require.NoError(t, json.Unmarshal(call("PUT", "/info/"+md5, `{"name":"Updated"}`, 200), &updated))
	require.Equal(t, "Updated", updated.Name)
	require.Empty(t, updated.Description)
	require.Empty(t, updated.Source)
	require.Equal(t, api.SeverityUnknown, updated.Severity)
	require.Equal(t, api.CategoryUnknown, updated.Category)
	require.Nil(t, updated.Sha256)
	require.Equal(t, *created.CreatedAt, *updated.CreatedAt)
	require.False(t, updated.UpdatedAt.Before(*created.UpdatedAt))
	call("PUT", "/info/"+strings.Repeat("0", 32), `{"name":"Missing"}`, 404)
	call("GET", "/info/"+strings.Repeat("0", 32), "", 404)
}

func TestConcurrentCreatesHaveOneWinner(t *testing.T) {
	pool, _ := database(t)
	svc := service.New(postgres.New(pool))
	var created, conflicts atomic.Int32
	var group sync.WaitGroup
	unexpected := make(chan error, 24)
	for range 24 {
		group.Go(func() {
			_, err := svc.Create(context.Background(), strings.ToUpper(md5), domain.ThreatInput{Name: "Concurrent"})
			switch {
			case err == nil:
				created.Add(1)
			case errors.Is(err, apperror.ErrAlreadyExists):
				conflicts.Add(1)
			default:
				unexpected <- err
			}
		})
	}
	group.Wait()
	close(unexpected)
	for err := range unexpected {
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, created.Load())
	require.EqualValues(t, 23, conflicts.Load())
	var count int
	require.NoError(t, pool.QueryRow(context.Background(), "SELECT count(*) FROM threats").Scan(&count))
	require.Equal(t, 1, count)
}

func TestConstraintsAndMigrationRoundTrip(t *testing.T) {
	pool, provider := database(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, `INSERT INTO threats(md5,name,severity) VALUES($1,'Threat','unsupported')`, md5)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23514", pgErr.Code)
	_, err = provider.Down(ctx)
	require.NoError(t, err)
	var table *string
	require.NoError(t, pool.QueryRow(ctx, "SELECT to_regclass('threats')::text").Scan(&table))
	require.Nil(t, table)
	_, err = provider.Up(ctx)
	require.NoError(t, err)
	threat, err := service.New(postgres.New(pool)).Create(ctx, md5, domain.ThreatInput{Name: "After migration"})
	require.NoError(t, err)
	require.Equal(t, md5, threat.MD5, fmt.Sprint(threat))
}

package config_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"threat-exchange/internal/config"

	"github.com/stretchr/testify/require"
)

func baseEnv(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"API_KEYS":     "first-development-key,second-development-key",
		"HTTP_ADDRESS": ":8080", "DATABASE_URL": "postgres://localhost/threats", "MIGRATIONS_DIR": "migrations",
		"RATE_LIMIT": "60", "RATE_WINDOW": "1m", "DB_TIMEOUT": "15s", "DB_QUERY_TIMEOUT": "5s", "SHUTDOWN_TIMEOUT": "5s",
		"TLS_CERT_FILE": "", "TLS_KEY_FILE": "",
	} {
		t.Setenv(key, value)
	}
}

func TestLoad(t *testing.T) {
	baseEnv(t)
	cfg, err := config.Load()
	require.NoError(t, err)
	require.Len(t, cfg.APIKeys, 2)
	require.Equal(t, 60, cfg.RateLimit)
	require.Equal(t, 5*time.Second, cfg.DBQueryTimeout)
}

func TestInvalidConfigurationFailsInsteadOfUsingDefaults(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"API_KEYS", ""}, {"API_KEYS", "short"}, {"API_KEYS", strings.Repeat("a", 257)},
		{"RATE_LIMIT", "not-a-number"}, {"RATE_LIMIT", "0"},
		{"RATE_WINDOW", "invalid"}, {"RATE_WINDOW", "0s"},
		{"DB_QUERY_TIMEOUT", "invalid"}, {"DB_QUERY_TIMEOUT", "0s"}, {"DB_QUERY_TIMEOUT", "-1s"},
		{"DB_QUERY_TIMEOUT", "14.001s"}, {"DB_QUERY_TIMEOUT", "15s"},
		{"DB_TIMEOUT", "-1s"}, {"SHUTDOWN_TIMEOUT", "invalid"},
		{"HTTP_ADDRESS", ""}, {"DATABASE_URL", ""}, {"MIGRATIONS_DIR", ""},
		{"TLS_CERT_FILE", "server.pem"}, {"TLS_KEY_FILE", "server.key"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			baseEnv(t)
			t.Setenv(tc.key, tc.value)
			_, err := config.Load()
			require.Error(t, err)
		})
	}
}

func TestDBQueryTimeoutDefaultsAndMaximum(t *testing.T) {
	baseEnv(t)
	require.NoError(t, os.Unsetenv("DB_QUERY_TIMEOUT"))
	cfg, err := config.Load()
	require.NoError(t, err)
	require.Equal(t, 5*time.Second, cfg.DBQueryTimeout)
	t.Setenv("DB_QUERY_TIMEOUT", "14s")
	cfg, err = config.Load()
	require.NoError(t, err)
	require.Equal(t, 14*time.Second, cfg.DBQueryTimeout)
	require.Less(t, cfg.DBQueryTimeout, config.HTTPWriteTimeout)
}

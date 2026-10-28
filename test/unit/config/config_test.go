package config_test

import (
	"strings"
	"testing"

	"threat-exchange/internal/config"

	"github.com/stretchr/testify/require"
)

func baseEnv(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"API_KEYS":     "first-development-key,second-development-key",
		"HTTP_ADDRESS": ":8080", "DATABASE_URL": "postgres://localhost/threats", "MIGRATIONS_DIR": "migrations",
		"RATE_LIMIT": "60", "RATE_WINDOW": "1m", "DB_TIMEOUT": "15s", "SHUTDOWN_TIMEOUT": "5s",
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
}

func TestInvalidConfigurationFailsInsteadOfUsingDefaults(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"API_KEYS", ""}, {"API_KEYS", "short"}, {"API_KEYS", strings.Repeat("a", 257)},
		{"RATE_LIMIT", "not-a-number"}, {"RATE_LIMIT", "0"},
		{"RATE_WINDOW", "invalid"}, {"RATE_WINDOW", "0s"},
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

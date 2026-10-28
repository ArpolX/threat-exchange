package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const HTTPWriteTimeout = 15 * time.Second

type Config struct {
	Environment     string
	HTTPAddress     string
	DatabaseURL     string
	MigrationsDir   string
	APIKeys         []string
	RateLimit       int
	RateWindow      time.Duration
	DBTimeout       time.Duration
	DBQueryTimeout  time.Duration
	ShutdownTimeout time.Duration
	TLSCertFile     string
	TLSKeyFile      string
}

func Load() (Config, error) {
	cfg := Config{
		Environment:   value("ENVIRONMENT", "development"),
		HTTPAddress:   value("HTTP_ADDRESS", ":8080"),
		DatabaseURL:   value("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/threats?sslmode=disable"),
		MigrationsDir: value("MIGRATIONS_DIR", "migrations"),
		TLSCertFile:   os.Getenv("TLS_CERT_FILE"), TLSKeyFile: os.Getenv("TLS_KEY_FILE"),
	}
	for _, key := range strings.Split(os.Getenv("API_KEYS"), ",") {
		key = strings.TrimSpace(key)
		if len(key) < 16 || len(key) > 256 {
			return Config{}, fmt.Errorf("API_KEYS must contain comma-separated keys of 16 to 256 bytes")
		}
		cfg.APIKeys = append(cfg.APIKeys, key)
	}
	if cfg.HTTPAddress == "" || cfg.DatabaseURL == "" || cfg.MigrationsDir == "" {
		return Config{}, fmt.Errorf("HTTP_ADDRESS, DATABASE_URL and MIGRATIONS_DIR must not be empty")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Config{}, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}
	var err error
	cfg.RateLimit, err = strconv.Atoi(value("RATE_LIMIT", "60"))
	if err != nil || cfg.RateLimit <= 0 {
		return Config{}, fmt.Errorf("RATE_LIMIT must be a positive integer")
	}
	for _, setting := range []struct {
		name     string
		fallback string
		target   *time.Duration
	}{
		{"RATE_WINDOW", "1m", &cfg.RateWindow},
		{"DB_TIMEOUT", "15s", &cfg.DBTimeout},
		{"DB_QUERY_TIMEOUT", "5s", &cfg.DBQueryTimeout},
		{"SHUTDOWN_TIMEOUT", "5s", &cfg.ShutdownTimeout},
	} {
		parsed, err := time.ParseDuration(value(setting.name, setting.fallback))
		if err != nil || parsed <= 0 {
			return Config{}, fmt.Errorf("%s must be a positive duration", setting.name)
		}
		*setting.target = parsed
	}
	if cfg.DBQueryTimeout > HTTPWriteTimeout-time.Second {
		return Config{}, fmt.Errorf("DB_QUERY_TIMEOUT must not exceed %s", HTTPWriteTimeout-time.Second)
	}
	return cfg, nil
}

func value(name, fallback string) string {
	if result, ok := os.LookupEnv(name); ok {
		return result
	}
	return fallback
}

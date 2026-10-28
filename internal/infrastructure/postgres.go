package infrastructure

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func ConnectPostgres(ctx context.Context, dsn string, queryTimeout time.Duration) (*pgxpool.Pool, error) {
	if queryTimeout <= 0 {
		return nil, fmt.Errorf("postgres query timeout must be positive")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres config: %w", err)
	}
	milliseconds := queryTimeout / time.Millisecond
	if queryTimeout%time.Millisecond != 0 {
		milliseconds++
	}
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(int64(milliseconds), 10)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	return pool, nil
}

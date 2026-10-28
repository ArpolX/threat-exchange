package postgres

import (
	"context"
	"errors"
	"fmt"

	"threat-exchange/internal/apperror"
	"threat-exchange/internal/domain"

	"github.com/jackc/pgx/v5"
)

func (r *Repository) Get(ctx context.Context, md5 string) (*domain.Threat, error) {
	threat, err := scanThreat(r.pool.QueryRow(ctx, `SELECT `+threatColumns+` FROM threats WHERE md5 = $1`, md5))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperror.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get threat: %w", err)
	}
	return threat, nil
}

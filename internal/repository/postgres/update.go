package postgres

import (
	"context"
	"errors"
	"fmt"

	"threat-exchange/internal/apperror"
	"threat-exchange/internal/domain"

	"github.com/jackc/pgx/v5"
)

func (r *Repository) Update(ctx context.Context, md5 string, input domain.ThreatInput) (*domain.Threat, error) {
	ctx, cancel := r.queryContext(ctx)
	defer cancel()

	row := r.pool.QueryRow(ctx, `UPDATE threats SET name = $2, description = $3, severity = $4,
  category = $5, source = $6, sha256 = $7, updated_at = clock_timestamp()
  WHERE md5 = $1 RETURNING `+threatColumns,
		md5, input.Name, input.Description, input.Severity, input.Category, input.Source, input.SHA256)
	threat, err := scanThreat(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperror.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("update threat: %w", err)
	}
	return threat, nil
}

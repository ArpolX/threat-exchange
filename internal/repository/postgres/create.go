package postgres

import (
	"context"
	"errors"
	"fmt"

	"threat-exchange/internal/apperror"
	"threat-exchange/internal/domain"

	"github.com/jackc/pgx/v5/pgconn"
)

func (r *Repository) Create(ctx context.Context, md5 string, input domain.ThreatInput) (*domain.Threat, error) {
	row := r.pool.QueryRow(ctx, `INSERT INTO threats (md5, name, description, severity, category, source, sha256)
  VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING `+threatColumns,
		md5, input.Name, input.Description, input.Severity, input.Category, input.Source, input.SHA256)
	threat, err := scanThreat(row)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "threats_pkey" {
		return nil, apperror.ErrAlreadyExists
	}
	if err != nil {
		return nil, fmt.Errorf("create threat: %w", err)
	}
	return threat, nil
}

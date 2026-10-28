package postgres

import (
	"context"

	"threat-exchange/internal/domain"

	"github.com/jackc/pgx/v5"
)

const threatColumns = `md5, name, description, severity, category, source, sha256, created_at, updated_at`

func scanThreat(row pgx.Row) (*domain.Threat, error) {
	var threat domain.Threat
	err := row.Scan(&threat.MD5, &threat.Name, &threat.Description, &threat.Severity,
		&threat.Category, &threat.Source, &threat.SHA256, &threat.CreatedAt, &threat.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &threat, nil
}

func (r *Repository) queryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, r.queryTimeout)
}

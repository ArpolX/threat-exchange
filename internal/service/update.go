package service

import (
	"context"

	"threat-exchange/internal/domain"
)

func (s *Service) Update(ctx context.Context, md5 string, input domain.ThreatInput) (*domain.Threat, error) {
	hash, err := normalizeMD5(md5)
	if err != nil {
		return nil, err
	}
	normalized, err := normalizeInput(input)
	if err != nil {
		return nil, err
	}
	return s.repository.Update(ctx, hash, normalized)
}

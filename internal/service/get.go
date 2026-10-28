package service

import (
	"context"

	"threat-exchange/internal/domain"
)

func (s *Service) Get(ctx context.Context, md5 string) (*domain.Threat, error) {
	hash, err := normalizeMD5(md5)
	if err != nil {
		return nil, err
	}
	return s.repository.Get(ctx, hash)
}

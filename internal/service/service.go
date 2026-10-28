package service

import (
	"context"

	"threat-exchange/internal/domain"
)

type Repository interface {
	Create(context.Context, string, domain.ThreatInput) (*domain.Threat, error)
	Get(context.Context, string) (*domain.Threat, error)
	Update(context.Context, string, domain.ThreatInput) (*domain.Threat, error)
}

type Service struct {
	repository Repository
}

func New(repository Repository) *Service {
	return &Service{repository: repository}
}

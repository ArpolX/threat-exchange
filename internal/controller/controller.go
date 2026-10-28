package controller

import (
	"context"

	"threat-exchange/internal/domain"

	"go.uber.org/zap"
)

type Service interface {
	Create(context.Context, string, domain.ThreatInput) (*domain.Threat, error)
	Get(context.Context, string) (*domain.Threat, error)
	Update(context.Context, string, domain.ThreatInput) (*domain.Threat, error)
}

type Controller struct {
	service Service
	logger  *zap.Logger
}

func New(service Service, logger *zap.Logger) *Controller {
	return &Controller{service: service, logger: logger}
}

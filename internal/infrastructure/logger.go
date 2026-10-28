package infrastructure

import (
	"fmt"

	"go.uber.org/zap"
)

func NewLogger(environment string) (*zap.Logger, error) {
	var log *zap.Logger
	var err error
	if environment == "production" {
		log, err = zap.NewProduction()
	} else {
		log, err = zap.NewDevelopment()
	}
	if err != nil {
		return nil, fmt.Errorf("create logger: %w", err)
	}
	return log, nil
}

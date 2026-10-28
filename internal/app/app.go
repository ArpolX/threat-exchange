package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"threat-exchange/internal/config"
	"threat-exchange/internal/controller"
	"threat-exchange/internal/http/handlers"
	"threat-exchange/internal/http/middleware"
	"threat-exchange/internal/infrastructure"
	"threat-exchange/internal/repository/postgres"
	"threat-exchange/internal/service"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func Run(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log, err := infrastructure.NewLogger(cfg.Environment)
	if err != nil {
		return err
	}
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	defer func() { _ = log.Sync() }()

	startupCtx, cancelStartup := context.WithTimeout(ctx, cfg.DBTimeout)
	defer cancelStartup()
	pool, err := infrastructure.ConnectPostgres(startupCtx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := infrastructure.Migrate(startupCtx, cfg.DatabaseURL, cfg.MigrationsDir); err != nil {
		return err
	}
	cancelStartup()

	repository := postgres.New(pool)
	threatService := service.New(repository)
	limiter, err := middleware.NewLimiter(cfg.RateLimit, cfg.RateWindow, time.Now)
	if err != nil {
		return err
	}
	ctrl := controller.New(threatService, log)
	router, err := handlers.NewRouter(ctrl, log, middleware.APIKeyAuth(cfg.APIKeys), limiter.Middleware())
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: cfg.HTTPAddress, Handler: router,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10,
		TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS12},
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("threat exchange API started", zap.String("address", cfg.HTTPAddress), zap.Bool("tls", cfg.TLSCertFile != ""))
		if cfg.TLSCertFile != "" {
			errCh <- server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			errCh <- server.ListenAndServe()
		}
	}()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP: %w", err)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return fmt.Errorf("shutdown HTTP: %w", err)
	}
	return nil
}

package handlers

import (
	"net/http"

	"threat-exchange/internal/controller"
	"threat-exchange/internal/http/middleware"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type Controller interface {
	Create(*gin.Context)
	Get(*gin.Context)
	Update(*gin.Context)
}

func NewRouter(ctrl Controller, logger *zap.Logger, auth, limiter gin.HandlerFunc) (*gin.Engine, error) {
	validator, err := middleware.ValidateRequest()
	if err != nil {
		return nil, err
	}

	router := gin.New()
	if err := router.SetTrustedProxies(nil); err != nil {
		return nil, err
	}
	router.HandleMethodNotAllowed = true
	router.Use(middleware.RequestLog(logger), middleware.Recovery(logger))
	router.NoRoute(func(c *gin.Context) { controller.WriteError(c, http.StatusNotFound, "route not found", "") })
	router.NoMethod(func(c *gin.Context) { controller.WriteError(c, http.StatusMethodNotAllowed, "method not allowed", "") })
	protected := router.Group("", auth, limiter, middleware.JSONBody(), validator)
	protected.POST("/info", ctrl.Create)
	protected.GET("/info/:md5", ctrl.Get)
	protected.PUT("/info/:md5", ctrl.Update)
	return router, nil
}

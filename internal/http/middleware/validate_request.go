package middleware

import (
	"fmt"

	"threat-exchange/api"
	"threat-exchange/internal/controller"

	"github.com/gin-gonic/gin"
	oapigin "github.com/oapi-codegen/gin-middleware"
)

func ValidateRequest() (gin.HandlerFunc, error) {
	spec, err := api.LoadSpecification()
	if err != nil {
		return nil, fmt.Errorf("load OpenAPI: %w", err)
	}
	spec.Security = nil
	return oapigin.OapiRequestValidatorWithOptions(spec, &oapigin.Options{
		ErrorHandler: func(c *gin.Context, message string, status int) {
			controller.WriteError(c, status, "invalid request", message)
		},
	}), nil
}

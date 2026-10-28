package controller

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"threat-exchange/api"
	"threat-exchange/internal/apperror"
	"threat-exchange/internal/domain"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func toInput(name string, description *string, severity *api.Severity, category *api.Category, source, sha256 *string) domain.ThreatInput {
	return domain.ThreatInput{Name: name, Description: text(description),
		Severity: domain.Severity(text(severity)), Category: domain.Category(text(category)),
		Source: text(source), SHA256: sha256}
}

func toResponse(threat *domain.Threat) api.ThreatResponse {
	created, updated := threat.CreatedAt.UTC(), threat.UpdatedAt.UTC()
	return api.ThreatResponse{Md5: threat.MD5, Name: threat.Name, Description: threat.Description,
		Severity: api.Severity(threat.Severity), Category: api.Category(threat.Category),
		Source: threat.Source, Sha256: threat.SHA256, CreatedAt: &created, UpdatedAt: &updated}
}

func text[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}

func decode(c *gin.Context, target any) bool {
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		WriteError(c, http.StatusBadRequest, "invalid JSON body", "")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		WriteError(c, http.StatusBadRequest, "body must contain a single JSON value", "")
		return false
	}
	return true
}

func (h *Controller) writeError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, apperror.ErrInvalidInput):
		WriteError(c, http.StatusBadRequest, "invalid input", err.Error())
	case errors.Is(err, apperror.ErrNotFound):
		WriteError(c, http.StatusNotFound, "threat not found", "")
	case errors.Is(err, apperror.ErrAlreadyExists):
		WriteError(c, http.StatusConflict, "threat with this MD5 already exists", "")
	default:
		h.logger.Error("request failed", zap.Error(err), zap.String("request_id", c.GetString("request_id")))
		WriteError(c, http.StatusInternalServerError, "internal server error", "")
	}
}

func WriteError(c *gin.Context, status int, message, details string) {
	response := api.ErrorResponse{Message: message}
	if details != "" {
		response.Details = &details
	}
	c.AbortWithStatusJSON(status, response)
}

package controller

import (
	"net/http"

	"threat-exchange/api"

	"github.com/gin-gonic/gin"
)

func (h *Controller) Create(c *gin.Context) {
	var request api.ThreatCreateRequest
	if !decode(c, &request) {
		return
	}
	input := toInput(request.Name, request.Description, request.Severity, request.Category, request.Source, request.Sha256)
	threat, err := h.service.Create(c.Request.Context(), request.Md5, input)
	if err != nil {
		h.writeError(c, err)
		return
	}
	c.Header("Location", "/info/"+threat.MD5)
	c.JSON(http.StatusCreated, toResponse(threat))
}

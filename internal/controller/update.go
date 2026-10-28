package controller

import (
	"net/http"

	"threat-exchange/api"

	"github.com/gin-gonic/gin"
)

func (h *Controller) Update(c *gin.Context) {
	var request api.ThreatUpdateRequest
	if !decode(c, &request) {
		return
	}
	input := toInput(request.Name, request.Description, request.Severity, request.Category, request.Source, request.Sha256)
	threat, err := h.service.Update(c.Request.Context(), c.Param("md5"), input)
	if err != nil {
		h.writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, toResponse(threat))
}

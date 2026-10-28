package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Controller) Get(c *gin.Context) {
	threat, err := h.service.Get(c.Request.Context(), c.Param("md5"))
	if err != nil {
		h.writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, toResponse(threat))
}

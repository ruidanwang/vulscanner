package handler

import (
	"github.com/gin-gonic/gin"
)

// @BasePath /api/

// PingExample godoc
// @Summary ping example
// @Schemes
// @Description do ping
// @Tags example
// @Accept json
// @Produce json
// @Success 200 {string} Helloworld
// @Router /health [get]
func Health(c *gin.Context) {
	c.JSON(200, gin.H{
		"status": "ok",
	})
}

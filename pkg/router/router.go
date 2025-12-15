package router

import (
	"github.com/gin-gonic/gin"
	"github.com/ruidanwang/vulscanner/vulscanner/pkg/handler"
)

func Register(r *gin.Engine) {
	api := r.Group("/api")

	api.GET("/health", handler.Health)
}

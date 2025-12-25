package router

import (
	"github.com/gin-gonic/gin"
	handler "github.com/ruidanwang/vulscanner/pkg/handler/health"
	portscan "github.com/ruidanwang/vulscanner/pkg/handler/portscan"
	"github.com/ruidanwang/vulscanner/pkg/handler/vulscan"
)

func Register(r *gin.Engine) {
	api := r.Group("/api")

	api.GET("/health", handler.Health)

	// 注册端口扫描路由
	api.POST("/scan/portscan", portscan.RunNaabuScan)

	api.POST("/scan/vulscan", vulscan.VulScan)
}

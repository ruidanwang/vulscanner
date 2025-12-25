package portscan

import (
	"context"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// ScanRequest 定义了端口扫描API的请求体结构
type ScanRequest struct {
	Hosts []string `json:"hosts" binding:"required"` // 要扫描的主机列表
	Ports string   `json:"ports" `                   // 要扫描的端口
	Others string  `json:"others"`
}

// code update

// RunNaabuScan 作为Gin的Handler，使用Naabu SDK执行主机和端口发现扫描。
func RunNaabuScan(c *gin.Context) {
	var req ScanRequest
	// 绑定JSON请求体到ScanRequest结构体
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数无效: " + err.Error()})
		return
	}

	// Naabu 使用 gologger，我们可以配置它以控制日志输出。
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)

	// 用于线程安全地收集扫描结果
	var results []*result.HostResult
	var mu sync.Mutex

	// 配置 Naabu 扫描选项
	options := runner.Options{
		// 从请求中获取要扫描的目标主机
		Host: req.Hosts,
		// 从请求中获取要扫描的端口
		Ports: req.Ports,

		// 设置扫描的线程数
		Threads: 100,

		// 定义结果回调函数。每当发现一个有开放端口的主机时，此函数将被调用。
		OnResult: func(hr *result.HostResult) {
			// 使用互斥锁来安全地追加结果
			mu.Lock()
			results = append(results, hr)
			mu.Unlock()

			// 仍然可以在服务器端打印日志
			gologger.Info().Msgf("发现主机: %s (%s)", hr.Host, hr.IP)
			for _, port := range hr.Ports {
				gologger.Info().Msgf("  -> 开放端口: %d/%s", port.Port, port.Protocol)
			}
		},
	}

	// 创建一个新的 Naabu runner
	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		gologger.Error().Msgf("无法创建 Naabu runner: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法创建扫描器"})
		return
	}
	defer naabuRunner.Close()

	// 开始枚举（扫描）
	// gologger.Info().Msgf("开始对目标 %v 扫描端口 %s", options.Host, options.Ports)
	if err := naabuRunner.RunEnumeration(context.Background()); err != nil {
		gologger.Error().Msgf("无法运行枚举: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "扫描执行失败"})
		return
	}
	gologger.Info().Msg("扫描完成。")

	// 以JSON格式返回收集到的所有结果
	c.JSON(http.StatusOK, gin.H{
		"message": "扫描完成",
		"results": results,
	})
}

package portscan

import (
	"context"
	"log"
	"net/http"
	"sync"

	"fmt"

	"net/netip"

	"github.com/gin-gonic/gin"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// ScanRequest 定义了端口扫描API的请求体结构
type ScanRequest struct {
	Hosts  []string `json:"hosts" binding:"required"` // 要扫描的主机列表
	Ports  string   `json:"ports" `                   // 要扫描的端口
	Others string   `json:"others"`
}

type ScanResultFP struct {
	Host     string
	Port     int
	Service  string
	Version  string
	Metadata interface{}
}

// code update

// func ScanWithfingerprintx(c *gin.Context) {
// 	target := "scanme.sh"
// 	ports := "21-23,80,443,3306,5432,6379,8080"

// 	// 步骤 1: 使用 naabu 进行快速端口扫描
// 	openPorts := performPortScan(target, ports)

// 	// 步骤 2: 使用 fingerprintx 对开放端口进行指纹识别
// 	fingerprints := performFingerprinting(target, openPorts)

// 	// 输出结果
// 	printResults(fingerprints)
// }

// // performPortScan 使用 naabu 执行端口扫描
// func performPortScan(target, ports string) []int {
// 	var openPorts []int
// 	var mu sync.Mutex

// 	options := runner.Options{
// 		Host:     goflags.StringSlice{target},
// 		ScanType: "c", // CONNECT scan (无需 root)
// 		Ports:    ports,
// 		Rate:     1000,
// 		Retries:  2,
// 		Timeout:  1000,
// 		Silent:   true,
// 		OnResult: func(hr *result.HostResult) {
// 			mu.Lock()
// 			defer mu.Unlock()
// 			for _, port := range hr.Ports {
// 				openPorts = append(openPorts, port.Port)
// 				log.Printf("[Naabu] 发现开放端口: %s:%d\n", hr.Host, port.Port)
// 			}
// 		},
// 	}

// 	naabuRunner, err := runner.NewRunner(&options)
// 	if err != nil {
// 		log.Fatal("初始化 naabu 失败:", err)
// 	}
// 	defer naabuRunner.Close()

// 	log.Printf("[*] 开始对 %s 进行端口扫描...\n", target)
// 	err = naabuRunner.RunEnumeration(context.Background())
// 	if err != nil {
// 		log.Fatal("端口扫描失败:", err)
// 	}

// 	return openPorts
// }

// // performFingerprinting 使用 fingerprintx 进行服务指纹识别
// func performFingerprinting(target string, ports []int) []ScanResultFP {
// 	var results []ScanResultFP

// 	// 创建 fingerprintx 扫描配置
// 	config := scan.Config{
// 		DefaultTimeout: 5000,  // 5秒超时
// 		FastMode:       false, // 完整扫描模式
// 		UDP:            false, // 只扫描 TCP
// 		Verbose:        true,
// 	}

// 	log.Printf("[*] 开始对 %d 个端口进行指纹识别...\n", len(ports))

// 	for _, port := range ports {
// 		// 构建目标地址
// 		addr, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", target, port))
// 		if err != nil {
// 			log.Printf("[!] 解析地址失败 %s:%d - %v\n", target, port, err)
// 			continue
// 		}

// 		// 执行指纹识别
// 		fpResult, err := scan.ScanTarget(addr, config, plugins.DEFAULT_PLUGINS)
// 		if err != nil {
// 			log.Printf("[!] 指纹识别失败 %s:%d - %v\n", target, port, err)
// 			continue
// 		}

// 		// 保存结果
// 		scanResult := ScanResultFP{
// 			Host:     target,
// 			Port:     port,
// 			Service:  fpResult.Protocol,
// 			Version:  getVersion(fpResult),
// 			Metadata: fpResult.Metadata,
// 		}

// 		results = append(results, scanResult)
// 		log.Printf("[FingerprintX] %s:%d -> %s %s\n",
// 			target, port, fpResult.Protocol, getVersion(fpResult))
// 	}

// 	return results
// }

// // getVersion 从 fingerprintx 结果中提取版本信息
// func getVersion(fpResult *plugins.ServiceFingerprint) string {
// 	if fpResult.Metadata == nil {
// 		return ""
// 	}

// 	// 根据不同服务类型提取版本信息
// 	switch m := fpResult.Metadata.(type) {
// 	case plugins.HTTPMetadata:
// 		return m.Version
// 	case plugins.SSHMetadata:
// 		return m.ServerID.Software
// 	case plugins.MySQLMetadata:
// 		return m.Version
// 	case plugins.PostgresMetadata:
// 		return m.Version
// 	// 可以添加更多服务类型
// 	default:
// 		return fmt.Sprintf("%v", m)
// 	}
// }

// // printResults 打印扫描和指纹识别结果
// func printResults(results []ScanResultFP) {
// 	fmt.Println("\n" + "="*60)
// 	fmt.Println("完整扫描结果")
// 	fmt.Println("=" * 60)

// 	for _, r := range results {
// 		fmt.Printf("\n主机: %s\n", r.Host)
// 		fmt.Printf("端口: %d\n", r.Port)
// 		fmt.Printf("服务: %s\n", r.Service)
// 		if r.Version != "" {
// 			fmt.Printf("版本: %s\n", r.Version)
// 		}
// 		if r.Metadata != nil {
// 			fmt.Printf("元数据: %+v\n", r.Metadata)
// 		}
// 		fmt.Println("-" * 60)
// 	}
// }

func ScanWithNMAP(c *gin.Context) {
	// 示例1: 使用 naabu 进行端口扫描，然后调用 nmap 进行服务检测
	options := runner.Options{
		Host:     goflags.StringSlice{"scanme.sh"},
		ScanType: "c",                 // "c" for CONNECT scan, "s" for SYN scan (需要 root)
		Ports:    "80,443,22,21,3306", // 指定端口
		OnResult: func(hr *result.HostResult) {
			// 处理扫描结果
			for _, port := range hr.Ports {
				log.Printf("[发现开放端口] %s:%d\n", hr.Host, port.Port)
			}
		},
		// Nmap 集成 - 对发现的端口进行服务检测
		Nmap:    true,
		NmapCLI: "nmap -sV -sC -oX nmap_output.xml", // 服务版本检测 + 默认脚本
		Silent:  false,
		Verbose: true,
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		log.Fatal(err)
	}
	defer naabuRunner.Close()

	// 执行扫描
	err = naabuRunner.RunEnumeration(context.Background())
	if err != nil {
		log.Fatal(err)
	}
}

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

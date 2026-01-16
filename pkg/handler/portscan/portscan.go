package portscan

import (
	"context"
	"encoding/xml"
	"log"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// ScanRequest 定义了端口扫描API的请求体结构
// type ScanRequest struct {
// 	Hosts  []string `json:"hosts" binding:"required"` // 要扫描的主机列表
// 	Ports  string   `json:"ports" `                   // 要扫描的端口
// 	Others string   `json:"others"`
// }

// ScanRequest 扫描请求
type ScanRequest struct {
	Hosts       []string `json:"hosts" binding:"required"` // 目标主机
	Ports       string   `json:"ports"`                    // 端口范围，默认常见端口
	ScanType    string   `json:"scan_type"`                // "syn" 或 "connect"
	Rate        int      `json:"rate"`                     // 扫描速率
	Timeout     int      `json:"timeout"`                  // 超时时间(ms)
	EnableNmap  bool     `json:"enable_nmap"`              // 是否启用 Nmap
	NmapOptions []string `json:"nmap_options"`             // Nmap 额外选项
	Verify      bool     `json:"verify"`                   // 是否验证端口
}

// ScanResponse 扫描响应
type ScanResponse struct {
	Code    int         `json:"code"`            // 状态码
	Message string      `json:"message"`         // 消息
	Data    *ScanResult `json:"data,omitempty"`  // 扫描结果
	Error   string      `json:"error,omitempty"` // 错误信息
}

// ScanResult 扫描结果
type ScanResult struct {
	ScanID     string        `json:"scan_id"`     // 扫描任务ID
	Target     string        `json:"target"`      // 目标
	StartTime  string        `json:"start_time"`  // 开始时间
	EndTime    string        `json:"end_time"`    // 结束时间
	Duration   string        `json:"duration"`    // 扫描耗时
	Status     string        `json:"status"`      // 状态: scanning, completed, failed
	TotalPorts int           `json:"total_ports"` // 扫描的端口总数
	OpenPorts  int           `json:"open_ports"`  // 开放端口数
	PortList   []PortInfo    `json:"port_list"`   // 端口列表
	Services   []ServiceInfo `json:"services"`    // 服务信息（Nmap结果）
}

// PortInfo 端口信息（Naabu结果）
type PortInfo struct {
	IP       string `json:"ip"`       // IP地址
	Port     int    `json:"port"`     // 端口号
	Protocol string `json:"protocol"` // 协议
	State    string `json:"state"`    // 状态
	IsCDN    bool   `json:"is_cdn"`   // 是否为CDN
	CDNName  string `json:"cdn_name"` // CDN名称
}

// ServiceInfo 服务信息（Nmap结果）
type ServiceInfo struct {
	IP        string         `json:"ip"`                   // IP地址
	Port      int            `json:"port"`                 // 端口号
	Protocol  string         `json:"protocol"`             // 协议
	State     string         `json:"state"`                // 状态
	Service   string         `json:"service"`              // 服务名称
	Product   string         `json:"product,omitempty"`    // 产品名称
	Version   string         `json:"version,omitempty"`    // 版本
	ExtraInfo string         `json:"extra_info,omitempty"` // 额外信息
	OSType    string         `json:"os_type,omitempty"`    // 操作系统类型
	Scripts   []ScriptResult `json:"scripts,omitempty"`    // 脚本扫描结果
}

// ScriptResult Nmap脚本结果
type ScriptResult struct {
	ID     string `json:"id"`     // 脚本ID
	Output string `json:"output"` // 输出内容
}

// ============= Nmap XML 解析结构 =============

type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
}

type NmapHost struct {
	Address NmapAddress `xml:"address"`
	Ports   NmapPorts   `xml:"ports"`
}

type NmapAddress struct {
	Addr string `xml:"addr,attr"`
}

type NmapPorts struct {
	Ports []NmapPort `xml:"port"`
}

type NmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    NmapState    `xml:"state"`
	Service  NmapService  `xml:"service"`
	Scripts  []NmapScript `xml:"script"`
}

type NmapState struct {
	State string `xml:"state,attr"`
}

type NmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	OSType    string `xml:"ostype,attr"`
}

type NmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// ============= 全局变量 =============

var (
	scanResults = make(map[string]*ScanResult)
	resultMutex sync.RWMutex
)

type ScanResultFP struct {
	Host     string
	Port     int
	Service  string
	Version  string
	Metadata interface{}
}

// code update

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

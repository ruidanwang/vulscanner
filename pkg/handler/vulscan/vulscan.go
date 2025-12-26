package vulscan

import (
	"context"
	"net/http"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"github.com/gin-gonic/gin"
)

type ScanRequest struct {
	Target string `json:"target" binding:"required"`
}

func VulScan(c *gin.Context) {
	results := make([]output.ResultEvent, 0)

	callback := func(event *output.ResultEvent) {
		// mu.Lock()
		// defer mu.Unlock()

		results = append(results, *event)
	}
	ne, err := nuclei.NewNucleiEngineCtx(context.Background(),
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"oast"}}),
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 6064}), // optionally enable metrics server for better observability
	)
	if err != nil {
		panic(err)
	}
	// load targets and optionally probe non http/https targets
	ne.LoadTargets([]string{"http://honey.scanme.sh"}, false)
	// err = ne.ExecuteWithCallback(nil)
	err = ne.ExecuteWithCallback(callback)
	if err != nil {
		panic(err)
	}
	defer ne.Close()

	c.JSON(http.StatusOK, gin.H{
		"count":   len(results),
		"results": results,
	})
	// target := "https://example.com"
	// template := "/opt/nuclei-templates/cves/2023/CVE-2023-12345.yaml"

	// cmd := exec.Command(
	// 	"nuclei",
	// 	"-u", target,
	// 	"-t", template,
	// 	"-json",
	// 	"-silent",
	// )

	// var out bytes.Buffer
	// cmd.Stdout = &out

	// if err := cmd.Run(); err != nil {
	// 	fmt.Println("scan error:", err)
	// 	return
	// }

	// fmt.Println(out.String())
}

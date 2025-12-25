package vulscan

import (
	"context"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"

	"github.com/gin-gonic/gin"
)

func VulScan(c *gin.Context) {
	ne, err := nuclei.NewNucleiEngineCtx(context.Background(),
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"oast"}}),
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 6064}), // optionally enable metrics server for better observability
	)
	if err != nil {
		panic(err)
	}
	// load targets and optionally probe non http/https targets
	ne.LoadTargets([]string{"http://honey.scanme.sh"}, false)
	err = ne.ExecuteWithCallback(nil)
	if err != nil {
		panic(err)
	}
	defer ne.Close()
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

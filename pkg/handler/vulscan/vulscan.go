package vulscan

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func VulScan(c *gin.Context) {
	target := "https://example.com"
	template := "/opt/nuclei-templates/cves/2023/CVE-2023-12345.yaml"

	cmd := exec.Command(
		"nuclei",
		"-u", target,
		"-t", template,
		"-json",
		"-silent",
	)

	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		fmt.Println("scan error:", err)
		return
	}

	fmt.Println(out.String())
}

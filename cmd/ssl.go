package cmd

import (
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

var sslCmd = &cobra.Command{
	Use:   "ssl [host:port or ip]",
	Short: "Hedefte SSL/TLS sertifika ve zayıf protokol denetimi yapar",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		core.PrintBanner(version)
		core.EnsureOutputDir("output")

		ip := target
		port := 443
		if strings.Contains(target, ":") {
			parts := strings.Split(target, ":")
			ip = parts[0]
			p, err := strconv.Atoi(parts[1])
			if err == nil {
				port = p
			}
		}

		finding := modules.AuditSSLService(ip, port, 4*time.Second)
		core.PrintSslTable([]core.SslFinding{finding})
		_ = core.SaveSslFindings([]core.SslFinding{finding}, "output/ssl_findings.json")
	},
}

func init() {
	RootCmd.AddCommand(sslCmd)
}

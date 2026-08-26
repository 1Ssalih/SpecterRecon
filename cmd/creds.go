package cmd

import (
	"time"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

var credsCmd = &cobra.Command{
	Use:   "creds [target-ip]",
	Short: "Hedef servisler üzerinde varsayılan kullanıcı adı/parola tespiti yapar",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		core.PrintBanner(version)
		verifyScopePermission(target)
		core.EnsureOutputDir("output")

		services, _ := core.LoadServices("output/services.json")
		if len(services) == 0 {
			services = []core.ServiceDetail{
				{IP: target, Port: 21, ServiceName: "ftp"},
				{IP: target, Port: 22, ServiceName: "ssh"},
				{IP: target, Port: 80, ServiceName: "http"},
			}
		}

		findings, _ := modules.AuditDefaultCredentialsMultiple(services, 3*time.Second, "output/creds_found.json")
		core.PrintCredTable(findings)
	},
}

func init() {
	RootCmd.AddCommand(credsCmd)
}

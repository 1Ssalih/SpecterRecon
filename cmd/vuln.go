package cmd

import (
	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

var (
	vulnInputFlag  string
	vulnOutputFlag string
)

var vulnCmd = &cobra.Command{
	Use:   "vuln",
	Short: "Servis listesi için CVE zafiyet eşleştirmesi yapar",
	Example: `  specter-recon vuln --authorized
  specter-recon vuln -i output/services.json --authorized`,
	Run: func(cmd *cobra.Command, args []string) {
		core.PrintBanner(version)
		core.EnsureOutputDir("output")
		services, err := core.LoadServices(vulnInputFlag)
		if err != nil || len(services) == 0 {
			core.LogError("Servis listesi okunamadı: %s", vulnInputFlag)
			return
		}
		if len(services) > 0 {
			verifyScopePermission(services[0].IP)
		}

		vulns, _ := modules.MatchVulnerabilities(services, "", true, vulnOutputFlag)
		core.PrintVulnsTable(vulns)
	},
}

func init() {
	vulnCmd.Flags().StringVarP(&vulnInputFlag, "input", "i", "output/services.json", "Servisler JSON dosyası")
	vulnCmd.Flags().StringVarP(&vulnOutputFlag, "output", "o", "output/vulns.json", "Çıktı JSON dosyası")

	RootCmd.AddCommand(vulnCmd)
}

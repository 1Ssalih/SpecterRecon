package cmd

import (
	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

var (
	repTargetFlag string
	repOutputFlag string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Mevcut JSON çıktılarından HTML raporu üretir",
	Run: func(cmd *cobra.Command, args []string) {
		core.PrintBanner(version)

		hosts, _ := core.LoadHosts("")
		ports, _ := core.LoadPorts("")
		services, _ := core.LoadServices("")
		vulns, _ := core.LoadVulns("")

		var findings []core.DirFuzzFinding
		_ = core.LoadJSON("output/dirs.json", &findings)

		report := modules.BuildCompleteReport(repTargetFlag, hosts, ports, services, vulns, findings, 0.0)
		out, err := modules.GenerateHTMLReport(report, "", repOutputFlag)
		if err == nil {
			core.PrintSummaryTable(report)
			core.LogSuccess("Rapor başarıyla oluşturuldu: %s", out)
		}
	},
}

func init() {
	reportCmd.Flags().StringVarP(&repTargetFlag, "target", "t", "Target Network", "Rapor hedef başlığı")
	reportCmd.Flags().StringVarP(&repOutputFlag, "output", "o", "output/report.html", "Çıktı HTML rapor dosyası")

	RootCmd.AddCommand(reportCmd)
}

package cmd

import (
	"path/filepath"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

var (
	repTargetFlag  string
	repOutputFlag  string
	repOutputDir   string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Mevcut JSON çıktılarından HTML raporu ve summary.txt üretir",
	Run: func(cmd *cobra.Command, args []string) {
		core.PrintBanner(version)
		core.EnsureOutputDir(repOutputDir)

		// JSON çıktılarını output dizininden oku
		dnsFindings, _ := core.LoadIPList(filepath.Join(repOutputDir, "ip_list.json"))
		hosts, _ := core.LoadHosts(filepath.Join(repOutputDir, "hosts.json"))
		ports, _ := core.LoadPorts(filepath.Join(repOutputDir, "ports.json"))
		services, _ := core.LoadServices(filepath.Join(repOutputDir, "services.json"))
		vulns, _ := core.LoadVulns(filepath.Join(repOutputDir, "vulns.json"))

		var findings []core.DirFuzzFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "dirs.json"), &findings)

		report := modules.BuildCompleteReport(repTargetFlag, dnsFindings, hosts, ports, services, vulns, findings, 0.0)

		// HTML raporu
		out, err := modules.GenerateHTMLReport(report, "", repOutputFlag)
		if err != nil {
			core.LogError("HTML raporu oluşturulamadı: %v", err)
			return
		}

		// summary.txt — tüm bulgular tek dosyada
		summaryPath := filepath.Join(repOutputDir, "summary.txt")
		if sErr := core.SaveSummaryTxt(repTargetFlag, hosts, ports, services, vulns, findings, 0.0, summaryPath); sErr == nil {
			core.LogSuccess("Tarama özeti kaydedildi: %s", summaryPath)
		}

		core.PrintSummaryTable(report)
		core.LogSuccess("Rapor başarıyla oluşturuldu: %s", out)
	},
}

func init() {
	reportCmd.Flags().StringVarP(&repTargetFlag, "target", "t", "Target Network", "Rapor hedef başlığı")
	reportCmd.Flags().StringVarP(&repOutputFlag, "output", "o", "output/report.html", "Çıktı HTML rapor dosyası")
	reportCmd.Flags().StringVarP(&repOutputDir, "output-dir", "d", "output", "JSON çıktılarının okunacağı dizin")

	RootCmd.AddCommand(reportCmd)
}

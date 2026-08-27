package cmd

import (
	"path/filepath"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

var (
	repTargetFlag string
	repOutputFlag string
	repOutputDir  string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Mevcut JSON çıktılarından HTML raporu ve summary.txt üretir",
	Example: `  # Mevcut tarama sonuçlarından rapor üret
  specter-recon report -t "Lab Target" -o output/report.html

  # Özel dizinden rapor üret
  specter-recon report -t "Production" -d scan_results/`,
	Run: func(cmd *cobra.Command, args []string) {
		core.PrintBanner(version)
		core.EnsureOutputDir(repOutputDir)

		// JSON çıktılarından oku
		dnsFindings, _ := core.LoadIPList(filepath.Join(repOutputDir, "ip_list.json"))
		hosts, _ := core.LoadHosts(filepath.Join(repOutputDir, "hosts.json"))
		ports, _ := core.LoadPorts(filepath.Join(repOutputDir, "ports.json"))
		services, _ := core.LoadServices(filepath.Join(repOutputDir, "services.json"))

		var findings []core.DirFuzzFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "dirs.json"), &findings)

		// Pasif genişletilmiş modül bulguları
		var sslFindings []core.SslFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "ssl_findings.json"), &sslFindings)

		var httpAuditFindings []core.HttpAuditFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "http_audit.json"), &httpAuditFindings)

		var sshFindings []core.SshAuditFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "ssh_audit.json"), &sshFindings)

		report := modules.BuildCompleteReport(repTargetFlag, dnsFindings, hosts, ports, services, findings, 0.0)

		report.SslFindings = sslFindings
		report.HttpAuditFindings = httpAuditFindings
		report.SshAuditFindings = sshFindings

		// HTML raporu
		out, err := modules.GenerateHTMLReport(report, "", repOutputFlag)
		if err != nil {
			core.LogError("HTML raporu oluşturulamadı: %v", err)
			return
		}

		// summary.txt — tüm bulgular tek dosyada
		summaryPath := filepath.Join(repOutputDir, "summary.txt")
		if sErr := core.SaveSummaryTxt(
			repTargetFlag, hosts, ports, services, findings, 0.0, summaryPath,
			sslFindings, httpAuditFindings, sshFindings,
		); sErr == nil {
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

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

		var sslFindings []core.SslFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "ssl_findings.json"), &sslFindings)

		var httpAuditFindings []core.HttpAuditFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "http_audit.json"), &httpAuditFindings)

		var smbFindings []core.SmbFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "smb_findings.json"), &smbFindings)

		var ftpFindings []core.FtpFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "ftp_findings.json"), &ftpFindings)

		var smtpFindings []core.SmtpFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "smtp_findings.json"), &smtpFindings)

		var snmpFindings []core.SnmpFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "snmp_findings.json"), &snmpFindings)

		var dbFindings []core.DbFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "db_findings.json"), &dbFindings)

		var sshFindings []core.SshAuditFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "ssh_audit.json"), &sshFindings)

		var credFindings []core.CredFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "creds_found.json"), &credFindings)

		var containerFindings []core.ContainerFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "container_findings.json"), &containerFindings)

		var ldapFindings []core.LdapFinding
		_ = core.LoadJSON(filepath.Join(repOutputDir, "ldap_findings.json"), &ldapFindings)

		report := modules.BuildCompleteReport(repTargetFlag, dnsFindings, hosts, ports, services, vulns, findings, 0.0)

		report.SslFindings = sslFindings
		report.HttpAuditFindings = httpAuditFindings
		report.SmbFindings = smbFindings
		report.FtpFindings = ftpFindings
		report.SmtpFindings = smtpFindings
		report.SnmpFindings = snmpFindings
		report.DbFindings = dbFindings
		report.SshAuditFindings = sshFindings
		report.CredFindings = credFindings
		report.ContainerFindings = containerFindings
		report.LdapFindings = ldapFindings

		// HTML raporu
		out, err := modules.GenerateHTMLReport(report, "", repOutputFlag)
		if err != nil {
			core.LogError("HTML raporu oluşturulamadı: %v", err)
			return
		}

		// summary.txt — tüm bulgular tek dosyada
		summaryPath := filepath.Join(repOutputDir, "summary.txt")
		if sErr := core.SaveSummaryTxt(
			repTargetFlag, hosts, ports, services, vulns, findings, 0.0, summaryPath,
			sslFindings, httpAuditFindings, smbFindings, ftpFindings, smtpFindings, snmpFindings, dbFindings, sshFindings, credFindings, containerFindings, ldapFindings,
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

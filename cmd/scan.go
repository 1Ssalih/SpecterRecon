package cmd

import (
	"fmt"
	"time"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

var (
	portsFlag       string
	threadsFlag     int
	delayFlag       int
	subdomainsFlag  bool
	skipDirfuzzFlag bool
	skipVulnFlag    bool
	outputDirFlag   string
	profileFlag     string // web, network, ad, database, ssl, full
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Profil tabanlı evrensel güvenlik taraması yürütür (--profile web|network|ad|database|ssl|full)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		core.PrintBanner(version)
		verifyScopePermission(target)
		core.EnsureOutputDir(outputDirFlag)

		startTime := time.Now()
		core.LogAudit("FULL_PIPELINE_START", target, fmt.Sprintf("profile=%s, ports=%s, threads=%d", profileFlag, portsFlag, threadsFlag), "SUCCESS")

		var dnsFindings []core.DNSFinding
		discoveryTarget := target

		// Step 0: DNS Enumeration (if target is a domain name)
		if modules.IsDomainName(target) {
			core.LogStep("Modül 0: DNS Enumeration")
			var uniqueIPs []string
			var err error
			dnsFindings, uniqueIPs, err = modules.EnumerateDNS(
				target,
				subdomainsFlag,
				"wordlists/subdomains.txt",
				threadsFlag,
				fmt.Sprintf("%s/ip_list.json", outputDirFlag),
			)
			if err == nil && len(dnsFindings) > 0 {
				core.PrintDNSTable(dnsFindings)
			}
			if len(uniqueIPs) > 0 {
				core.LogInfo("DNS üzerinden %d IP adresi çıkarıldı.", len(uniqueIPs))
			}
		} else {
			core.LogInfo("Hedef doğrudan IP/CIDR olarak algılandı ('%s'), DNS Enumeration atlandı.", target)
		}

		// Step 1: Host Discovery
		core.LogStep("Adım 1: Host Discovery")
		var hosts []core.HostInfo
		if len(dnsFindings) > 0 {
			for _, df := range dnsFindings {
				foundHosts, _ := modules.DiscoverHosts(df.IP, nil, 2*time.Second, threadsFlag, "")
				if len(foundHosts) > 0 {
					for i := range foundHosts {
						foundHosts[i].Hostname = df.Hostname
					}
					hosts = append(hosts, foundHosts...)
				} else {
					h := core.NewHostInfo(df.IP, "dns_resolved")
					h.Hostname = df.Hostname
					hosts = append(hosts, h)
				}
			}
			_ = core.SaveHosts(hosts, fmt.Sprintf("%s/hosts.json", outputDirFlag))
		} else {
			hosts, _ = modules.DiscoverHosts(discoveryTarget, nil, 2*time.Second, threadsFlag, fmt.Sprintf("%s/hosts.json", outputDirFlag))
		}

		if len(hosts) == 0 {
			core.LogWarning("'%s' için canlı host tespit edilemedi. Doğrudan hedefe bağlanmayı deniyoruz...", target)
			hosts = []core.HostInfo{core.NewHostInfo(target, "direct")}
		}
		core.PrintHostsTable(hosts)

		// Step 2: Port Scanning
		core.LogStep("Adım 2: Port & Servis Taraması")
		var targetIPs []string
		seenIPs := make(map[string]bool)
		for _, h := range hosts {
			if !seenIPs[h.IP] {
				seenIPs[h.IP] = true
				targetIPs = append(targetIPs, h.IP)
			}
		}
		parsedPorts := modules.ParsePortSpecs(portsFlag)
		openPorts, _ := modules.ScanMultipleHosts(targetIPs, parsedPorts, threadsFlag, 1500*time.Millisecond, fmt.Sprintf("%s/ports.json", outputDirFlag))
		if len(openPorts) == 0 {
			core.LogWarning("Hiçbir açık port tespit edilemedi. Tarama sonlandırılıyor.")
			earlyDuration := time.Since(startTime).Seconds()
			report := modules.BuildCompleteReport(target, dnsFindings, hosts, nil, nil, nil, nil, earlyDuration)
			report.ScanProfile = profileFlag
			_, _ = modules.GenerateHTMLReport(report, "", fmt.Sprintf("%s/report.html", outputDirFlag))
			_ = core.SaveSummaryTxt(target, hosts, nil, nil, nil, nil, earlyDuration, fmt.Sprintf("%s/summary.txt", outputDirFlag))
			core.PrintSummaryTable(report)
			return
		}
		core.PrintPortsTable(openPorts)

		// Step 3: Banner Grabbing & Service Detection
		core.LogStep("Adım 3: Banner Grabbing & Versiyon Tespiti")
		services, _ := modules.GrabBannersAndServices(openPorts, min(30, threadsFlag), 3500*time.Millisecond, fmt.Sprintf("%s/services.json", outputDirFlag))
		core.PrintServicesTable(services)

		// Step 4: Vulnerability / CVE Matching
		var vulns []core.VulnerabilityInfo
		if !skipVulnFlag {
			core.LogStep("Adım 4: CVE & Zafiyet Eşleştirmesi")
			vulns, _ = modules.MatchVulnerabilities(services, "", true, fmt.Sprintf("%s/vulns.json", outputDirFlag))
			core.PrintVulnsTable(vulns)
		} else {
			core.LogInfo("CVE eşleştirme adımı atlandı (--skip-vuln).")
		}

		// --- PROFİL TABANLI GÜVENLİK MODÜLLERİ ---
		var sslFindings []core.SslFinding
		var httpAuditFindings []core.HttpAuditFinding
		var smbFindings []core.SmbFinding
		var ftpFindings []core.FtpFinding
		var smtpFindings []core.SmtpFinding
		var snmpFindings []core.SnmpFinding
		var dbFindings []core.DbFinding
		var sshFindings []core.SshAuditFinding
		var credFindings []core.CredFinding
		var containerFindings []core.ContainerFinding
		var ldapFindings []core.LdapFinding
		var dirFindings []core.DirFuzzFinding

		prof := profileFlag
		runAll := prof == "full"

		// 1. SSL/TLS Audit (web, network, ssl, full)
		if runAll || prof == "web" || prof == "network" || prof == "ssl" {
			core.LogStep("Genişletilmiş Modül: SSL/TLS Sertifika & Protokol Denetimi")
			sslFindings, _ = modules.AuditSSLMultiple(services, 4*time.Second, fmt.Sprintf("%s/ssl_findings.json", outputDirFlag))
			core.PrintSslTable(sslFindings)
		}

		// 2. HTTP Security Audit (web, full)
		if runAll || prof == "web" {
			core.LogStep("Genişletilmiş Modül: HTTP Güvenlik Denetimi (Headers, CORS, Methods)")
			httpAuditFindings, _ = modules.AuditHTTPMultiple(services, 5*time.Second, fmt.Sprintf("%s/http_audit.json", outputDirFlag))
			core.PrintHttpAuditTable(httpAuditFindings)
		}

		// 3. FTP Audit (network, full)
		if runAll || prof == "network" {
			core.LogStep("Genişletilmiş Modül: FTP Anonymous Login & Write Check")
			ftpFindings, _ = modules.AuditFTPMultiple(services, 4*time.Second, fmt.Sprintf("%s/ftp_findings.json", outputDirFlag))
			core.PrintFtpTable(ftpFindings)
		}

		// 4. SMB Audit (network, ad, full)
		if runAll || prof == "network" || prof == "ad" {
			core.LogStep("Genişletilmiş Modül: SMB / NetBIOS (Null Session, SMBv1, Signing)")
			smbFindings, _ = modules.AuditSMBMultiple(services, 4*time.Second, fmt.Sprintf("%s/smb_findings.json", outputDirFlag))
			core.PrintSmbTable(smbFindings)
		}

		// 5. LDAP Audit (ad, full)
		if runAll || prof == "ad" {
			core.LogStep("Genişletilmiş Modül: LDAP / Active Directory Numaralandırma")
			ldapFindings, _ = modules.AuditLDAPMultiple(services, 4*time.Second, fmt.Sprintf("%s/ldap_findings.json", outputDirFlag))
		}

		// 6. Database Audit (database, full)
		if runAll || prof == "database" {
			core.LogStep("Genişletilmiş Modül: Veritabanı Güvenlik Denetimi (Redis, Mongo, MySQL, Postgres)")
			dbFindings, _ = modules.AuditDatabaseMultiple(services, 4*time.Second, fmt.Sprintf("%s/db_findings.json", outputDirFlag))
			core.PrintDbTable(dbFindings)
		}

		// 7. SMTP Audit (network, full)
		if runAll || prof == "network" {
			core.LogStep("Genişletilmiş Modül: SMTP Open Relay & VRFY Check")
			smtpFindings, _ = modules.AuditSMTPMultiple(services, 4*time.Second, fmt.Sprintf("%s/smtp_findings.json", outputDirFlag))
		}

		// 8. SNMP Audit (network, full)
		if runAll || prof == "network" {
			core.LogStep("Genişletilmiş Modül: SNMP Community String Brute-Force")
			snmpFindings, _ = modules.AuditSNMPMultiple(hosts, 2*time.Second, fmt.Sprintf("%s/snmp_findings.json", outputDirFlag))
		}

		// 9. SSH Audit (network, full)
		if runAll || prof == "network" {
			core.LogStep("Genişletilmiş Modül: SSH Algoritma & Konfigürasyon Denetimi")
			sshFindings, _ = modules.AuditSSHMultiple(services, 4*time.Second, fmt.Sprintf("%s/ssh_audit.json", outputDirFlag))
		}

		// 10. Container / DevOps Audit (cloud, full)
		if runAll || prof == "cloud" {
			core.LogStep("Genişletilmiş Modül: Container & Cloud DevOps (Docker, K8s, etcd, Consul)")
			containerFindings, _ = modules.AuditContainerMultiple(services, 4*time.Second, fmt.Sprintf("%s/container_findings.json", outputDirFlag))
		}

		// 11. Default Credentials Audit (network, ad, database, full)
		if runAll || prof == "network" || prof == "ad" || prof == "database" {
			core.LogStep("Genişletilmiş Modül: Varsayılan Kredi (Default Credential) Tespiti")
			credFindings, _ = modules.AuditDefaultCredentialsMultiple(services, 3*time.Second, fmt.Sprintf("%s/creds_found.json", outputDirFlag))
			core.PrintCredTable(credFindings)
		}

		// 12. Web Directory Fuzzing (web, full)
		if !skipDirfuzzFlag && (runAll || prof == "web") {
			core.LogStep("Adım 5: Web Dizin & Dosya Fuzzing (Akıllı Wordlist)")
			dirFindings, _ = modules.RunDirFuzzing(
				services,
				"wordlists/common.txt",
				"wordlists/sensitive.txt",
				min(25, threadsFlag),
				delayFlag,
				fmt.Sprintf("%s/dirs.json", outputDirFlag),
				fmt.Sprintf("%s/findings.txt", outputDirFlag),
			)
			core.PrintDirFindingsTable(dirFindings)
		}

		// Step 6: Reporting
		core.LogStep("Adım 6: Raporlama")
		duration := time.Since(startTime).Seconds()
		report := modules.BuildCompleteReport(target, dnsFindings, hosts, openPorts, services, vulns, dirFindings, duration)
		report.ScanProfile = profileFlag

		// Attach extended findings
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

		_, _ = modules.GenerateHTMLReport(report, "", fmt.Sprintf("%s/report.html", outputDirFlag))

		// summary.txt
		summaryPath := fmt.Sprintf("%s/summary.txt", outputDirFlag)
		if err := core.SaveSummaryTxt(
			target, hosts, openPorts, services, vulns, dirFindings, duration, summaryPath,
			sslFindings, httpAuditFindings, smbFindings, ftpFindings, smtpFindings, snmpFindings, dbFindings, sshFindings, credFindings, containerFindings, ldapFindings,
		); err == nil {
			core.LogSuccess("Tarama özeti kaydedildi: %s", summaryPath)
		}

		core.PrintSummaryTable(report)
	},
}

func init() {
	scanCmd.Flags().StringVarP(&portsFlag, "ports", "p", "top-100", "Taranacak portlar: 'top-20', 'top-100', 'top-1000', '1-1024', '80,443'")
	scanCmd.Flags().IntVarP(&threadsFlag, "threads", "t", 50, "Eşzamanlı bağlantı limiti")
	scanCmd.Flags().IntVarP(&delayFlag, "delay", "d", 0, "İstekler arası gecikme (ms) — Stealth modu")
	scanCmd.Flags().BoolVar(&subdomainsFlag, "subdomains", false, "Domain taramasında subdomain brute-force'u aktif eder")
	scanCmd.Flags().BoolVar(&skipDirfuzzFlag, "skip-dirfuzz", false, "Dizin fuzzing adımını atla")
	scanCmd.Flags().BoolVar(&skipVulnFlag, "skip-vuln", false, "CVE zafiyet eşleştirme adımını atla")
	scanCmd.Flags().StringVarP(&outputDirFlag, "output-dir", "o", "output", "Çıktı klasörü")
	scanCmd.Flags().StringVar(&profileFlag, "profile", "full", "Tarama profili: 'web', 'network', 'ad', 'database', 'ssl', 'cloud', 'full'")

	RootCmd.AddCommand(scanCmd)
}

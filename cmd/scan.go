package cmd

import (
	"fmt"
	"time"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

// minInt returns the smaller of two integers (Go 1.19 compatibility)
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var (
	portsFlag        string
	threadsFlag      int
	delayFlag        int
	subdomainsFlag   bool
	skipDirfuzzFlag  bool
	outputDirFlag    string
	extendedFlag     bool   // --extended: SSL/HTTP/SSH audit modüllerini aktif eder
	wordlistSizeFlag string // --wordlist-size: quick (küçük listeler) veya full (SecLists)
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Hedef üzerinde DNS + Discovery + Port + Banner + DirFuzz recon pipeline'ı çalıştırır",
	Long: `Hedef üzerinde otomatik keşif (recon) pipeline'ı çalıştırır.

Varsayılan olarak çekirdek modüller çalışır: DNS, Host Discovery, Port Scan,
Banner Grabbing ve Web Directory Fuzzing (Akıllı Wordlist / SecLists).

--extended bayrağıyla pasif genişletilmiş modüller de aktif edilir:
SSL/TLS Sertifika Audit, HTTP Security Headers Audit ve SSH Konfigürasyon Audit.`,
	Example: `  # Temel recon taraması
  specter-recon scan example.com --authorized

  # Subdomain brute-force dahil
  specter-recon scan example.com --subdomains --authorized

  # Genişletilmiş modüllerle (SSL + HTTP Audit + SSH Audit)
  specter-recon scan example.com --extended --authorized

  # Kapsamlı SecLists wordlist ile derin web dizin taraması
  specter-recon scan example.com --wordlist-size full --authorized

  # Özel port aralığı ve thread limiti ile
  specter-recon scan 192.168.1.10 -p 1-1024 -t 100 --authorized`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		core.PrintBanner(version)
		if !verifyScopePermission(target) {
			return
		}
		core.EnsureOutputDir(outputDirFlag)

		startTime := time.Now()
		profileLabel := "basic"
		if extendedFlag {
			profileLabel = "extended"
		}
		core.LogAudit("FULL_PIPELINE_START", target, fmt.Sprintf("profile=%s, ports=%s, threads=%d", profileLabel, portsFlag, threadsFlag), "SUCCESS")

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
			report := modules.BuildCompleteReport(target, dnsFindings, hosts, nil, nil, nil, earlyDuration)
			report.ScanProfile = profileLabel
			_, _ = modules.GenerateHTMLReport(report, "", fmt.Sprintf("%s/report.html", outputDirFlag))
			_ = core.SaveSummaryTxt(target, hosts, nil, nil, nil, earlyDuration, fmt.Sprintf("%s/summary.txt", outputDirFlag))
			core.PrintSummaryTable(report)
			return
		}
		core.PrintPortsTable(openPorts)

		// Step 3: Banner Grabbing & Service Detection
		core.LogStep("Adım 3: Banner Grabbing & Versiyon Tespiti")
		services, _ := modules.GrabBannersAndServices(openPorts, minInt(30, threadsFlag), 3500*time.Millisecond, fmt.Sprintf("%s/services.json", outputDirFlag))
		core.PrintServicesTable(services)

		// --- GENİŞLETİLMİŞ PASİF MODÜLLER (--extended) ---
		var sslFindings []core.SslFinding
		var httpAuditFindings []core.HttpAuditFinding
		var sshFindings []core.SshAuditFinding

		if extendedFlag {
			// SSL/TLS Audit
			core.LogStep("Genişletilmiş Modül: SSL/TLS Sertifika & Protokol Denetimi")
			sslFindings, _ = modules.AuditSSLMultiple(services, 4*time.Second, fmt.Sprintf("%s/ssl_findings.json", outputDirFlag))
			core.PrintSslTable(sslFindings)

			// HTTP Security Audit
			core.LogStep("Genişletilmiş Modül: HTTP Güvenlik Denetimi (Headers, CORS, Methods)")
			httpAuditFindings, _ = modules.AuditHTTPMultiple(services, 5*time.Second, fmt.Sprintf("%s/http_audit.json", outputDirFlag))
			core.PrintHttpAuditTable(httpAuditFindings)

			// SSH Audit
			core.LogStep("Genişletilmiş Modül: SSH Algoritma & Konfigürasyon Denetimi")
			sshFindings, _ = modules.AuditSSHMultiple(services, 4*time.Second, fmt.Sprintf("%s/ssh_audit.json", outputDirFlag))
		}

		// Step 4: Web Directory Fuzzing
		var dirFindings []core.DirFuzzFinding
		if !skipDirfuzzFlag {
			core.LogStep("Adım 4: Web Dizin & Dosya Fuzzing (Akıllı Wordlist / SecLists)")

			defaultWordlist := "wordlists/common.txt"
			sensitiveWordlist := "wordlists/sensitive.txt"
			if wordlistSizeFlag == "full" {
				defaultWordlist = "wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
				sensitiveWordlist = "wordlists/sensitive.txt"
			}

			dirFindings, _ = modules.RunDirFuzzing(
				services,
				wordlistSizeFlag,
				defaultWordlist,
				sensitiveWordlist,
				minInt(25, threadsFlag),
				delayFlag,
				fmt.Sprintf("%s/dirs.json", outputDirFlag),
				fmt.Sprintf("%s/findings.txt", outputDirFlag),
			)
			core.PrintDirFindingsTable(dirFindings)
		}

		// Step 5: Reporting
		core.LogStep("Adım 5: Raporlama")
		duration := time.Since(startTime).Seconds()
		report := modules.BuildCompleteReport(target, dnsFindings, hosts, openPorts, services, dirFindings, duration)
		report.ScanProfile = profileLabel

		// Attach extended findings
		report.SslFindings = sslFindings
		report.HttpAuditFindings = httpAuditFindings
		report.SshAuditFindings = sshFindings

		_, _ = modules.GenerateHTMLReport(report, "", fmt.Sprintf("%s/report.html", outputDirFlag))

		// summary.txt
		summaryPath := fmt.Sprintf("%s/summary.txt", outputDirFlag)
		if err := core.SaveSummaryTxt(
			target, hosts, openPorts, services, dirFindings, duration, summaryPath,
			sslFindings, httpAuditFindings, sshFindings,
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
	scanCmd.Flags().StringVarP(&outputDirFlag, "output-dir", "o", "output", "Çıktı klasörü")
	scanCmd.Flags().BoolVar(&extendedFlag, "extended", false, "Genişletilmiş pasif modülleri aktif eder (SSL/TLS + HTTP Audit + SSH Audit)")
	scanCmd.Flags().StringVar(&wordlistSizeFlag, "wordlist-size", "quick", "Wordlist boyutu: 'quick' (küçük/hızlı listeler) veya 'full' (SecLists)")

	RootCmd.AddCommand(scanCmd)
}

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
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Tüm adımları (DNS Enum -> Discovery -> Port Scan -> Banner -> CVE Match -> Dir Fuzz -> Report) sırasıyla çalıştırır",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		core.PrintBanner(version)
		verifyScopePermission(target)
		core.EnsureOutputDir(outputDirFlag)

		startTime := time.Now()
		core.LogAudit("FULL_PIPELINE_START", target, fmt.Sprintf("ports=%s, threads=%d, subdomains=%v", portsFlag, threadsFlag, subdomainsFlag), "SUCCESS")

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
				// Use discovered IP(s) for downstream discovery & scanning
				core.LogInfo("DNS üzerinden %d IP adresi çıkarıldı.", len(uniqueIPs))
			}
		} else {
			core.LogInfo("Hedef doğrudan IP/CIDR olarak algılandı ('%s'), DNS Enumeration atlandı.", target)
		}

		// Step 1: Host Discovery
		core.LogStep("Adım 1: Host Discovery")
		var hosts []core.HostInfo
		if len(dnsFindings) > 0 {
			// Probe each resolved DNS host
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

		// Step 5: Directory & File Bruteforce
		var findings []core.DirFuzzFinding
		if !skipDirfuzzFlag {
			core.LogStep("Adım 5: Web Dizin & Dosya Fuzzing (Akıllı Wordlist)")
			findings, _ = modules.RunDirFuzzing(
				services,
				"wordlists/common.txt",
				"wordlists/sensitive.txt",
				min(25, threadsFlag),
				delayFlag,
				fmt.Sprintf("%s/dirs.json", outputDirFlag),
				fmt.Sprintf("%s/findings.txt", outputDirFlag),
			)
			core.PrintDirFindingsTable(findings)
		} else {
			core.LogInfo("Web dizin fuzzing adımı atlandı (--skip-dirfuzz).")
		}

		// Step 6: Reporting
		core.LogStep("Adım 6: Raporlama")
		duration := time.Since(startTime).Seconds()
		report := modules.BuildCompleteReport(target, dnsFindings, hosts, openPorts, services, vulns, findings, duration)
		_, _ = modules.GenerateHTMLReport(report, "", fmt.Sprintf("%s/report.html", outputDirFlag))

		// summary.txt — tüm bulgular tek bir dosyada + terminale de yazılır
		summaryPath := fmt.Sprintf("%s/summary.txt", outputDirFlag)
		if err := core.SaveSummaryTxt(target, hosts, openPorts, services, vulns, findings, duration, summaryPath); err == nil {
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

	RootCmd.AddCommand(scanCmd)
}

package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

var (
	portsFlag        string
	threadsFlag      int
	delayFlag        int
	subdomainsFlag   bool
	skipDirfuzzFlag  bool
	outputDirFlag    string
	extendedFlag     bool   // --extended: SSL/HTTP/SSH audit modüllerini aktif eder
	wordlistSizeFlag string // --wordlist-size: quick (küçük listeler) veya full (SecLists)
	profileFlag      string // --profile: aggressive | balanced | stealth
	nmapXMLFlag      string // --nmap-xml: Nmap XML import dosyası
	masscanJSONFlag  string // --masscan-json: Masscan JSON import dosyası
	useMasscanFlag   bool   // --use-masscan: Masscan subprocess çalıştır
	useNmapNSEFlag   bool   // --use-nmap-nse: Nmap NSE subprocess çalıştır
)

var scanCmd = &cobra.Command{
	Use:          "scan [target]",
	Short:        "Hedef üzerinde DNS + Discovery + Port + Banner + DirFuzz recon pipeline'ı çalıştırır",
	SilenceUsage: true,
	Long: `Hedef üzerinde otomatik keşif (recon) pipeline'ı çalıştırır.

Tarama Profilleri (--profile):
  • balanced   : Native Go worker pool (Varsayılan, dengeli ve kararlı)
  • aggressive : Masscan (raw SYN) + Nmap NSE + SecLists Full Fuzzing
  • stealth    : Düşük worker, randomize gecikmeli istekler, Masscan/NSE kapalı

Entegrasyon Modları:
  • --nmap-xml      : Önceden alınmış Nmap XML çıktısını içe aktarır
  • --masscan-json  : Önceden alınmış Masscan JSON çıktısını içe aktarır
  • --use-masscan   : Masscan sürecini otomatik tetikler
  • --use-nmap-nse  : Tespit edilen servislere özel NSE scriptlerini tetikler`,
	Example: `  # Temel recon taraması (Balanced profil)
  specter-recon scan example.com --authorized

  # Saldırgan / Hızlı Profil (Masscan + Nmap NSE)
  specter-recon scan 10.0.0.0/16 --profile aggressive --authorized

  # Gizli / Stealth Profil (Gecikmeli, sessiz)
  specter-recon scan example.com --profile stealth -d 100 --authorized

  # Nmap XML İçe Aktarma (Import Modu)
  specter-recon scan --nmap-xml nmap_results.xml --authorized

  # Masscan JSON İçe Aktarma ve Doğrulama
  specter-recon scan --masscan-json masscan_out.json --authorized`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		if !verifyScopePermission(target) {
			return
		}
		core.EnsureOutputDir(outputDirFlag)

		startTime := time.Now()

		// Apply Profile Configurations
		profile := strings.ToLower(profileFlag)
		if profile == "" {
			profile = "balanced"
		}
		if profile == "aggressive" {
			wordlistSizeFlag = "full"
			if threadsFlag < 100 {
				threadsFlag = 100
			}
			if !cmd.Flags().Changed("use-masscan") && modules.CheckToolAvailable("masscan") {
				useMasscanFlag = true
			}
			if !cmd.Flags().Changed("use-nmap-nse") && modules.CheckToolAvailable("nmap") {
				useNmapNSEFlag = true
			}
		} else if profile == "stealth" {
			if delayFlag == 0 {
				delayFlag = 100
			}
			if threadsFlag > 20 {
				threadsFlag = 20
			}
			useMasscanFlag = false
			useNmapNSEFlag = false
		}

		core.LogInfo("Seçilen Tarama Profili: [%s] (Threads: %d, Gecikme: %dms, Wordlist: %s)",
			strings.ToUpper(profile), threadsFlag, delayFlag, strings.ToUpper(wordlistSizeFlag))
		core.LogAudit("FULL_PIPELINE_START", target, fmt.Sprintf("profile=%s, ports=%s, threads=%d, masscan=%v, nse=%v",
			profile, portsFlag, threadsFlag, useMasscanFlag, useNmapNSEFlag), "SUCCESS")

		var dnsFindings []core.DNSFinding
		discoveryTarget := target

		// Step 0: DNS Enumeration (if target is a domain name and no nmap-xml import)
		if nmapXMLFlag == "" && masscanJSONFlag == "" && modules.IsDomainName(target) {
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
		} else if !modules.IsDomainName(target) {
			core.LogInfo("Hedef doğrudan IP/CIDR olarak algılandı ('%s'), DNS Enumeration atlandı.", target)
		}

		// Step 1: Host Discovery
		core.LogStep("Adım 1: Host Discovery")
		var hosts []core.HostInfo
		if len(dnsFindings) > 0 {
			seenDiscoveryIPs := make(map[string]string)
			for _, df := range dnsFindings {
				if df.IP != "" {
					if existing, exists := seenDiscoveryIPs[df.IP]; !exists || (existing == target && df.Hostname != target) {
						seenDiscoveryIPs[df.IP] = df.Hostname
					}
				}
			}
			for ip, hn := range seenDiscoveryIPs {
				foundHosts, _ := modules.DiscoverHosts(ip, nil, 2*time.Second, threadsFlag, "")
				if len(foundHosts) > 0 {
					for i := range foundHosts {
						foundHosts[i].Hostname = hn
					}
					hosts = append(hosts, foundHosts...)
				} else {
					h := core.NewHostInfo(ip, "dns_resolved")
					h.Hostname = hn
					hosts = append(hosts, h)
				}
			}
			_ = core.SaveHosts(hosts, fmt.Sprintf("%s/hosts.json", outputDirFlag))
		} else if nmapXMLFlag == "" && masscanJSONFlag == "" {
			hosts, _ = modules.DiscoverHosts(discoveryTarget, nil, 2*time.Second, threadsFlag, fmt.Sprintf("%s/hosts.json", outputDirFlag))
		}

		if len(hosts) == 0 && nmapXMLFlag == "" && masscanJSONFlag == "" {
			core.LogWarning("'%s' için canlı host tespit edilemedi. Doğrudan hedefe bağlanmayı deniyoruz...", target)
			hosts = []core.HostInfo{core.NewHostInfo(target, "direct")}
		}
		if len(hosts) > 0 {
			core.PrintHostsTable(hosts)
		}

		// Step 2: Port Scanning (Import / Masscan / Native)
		core.LogStep("Adım 2: Port & Servis Taraması")
		var (
			openPorts        []core.PortInfo
			conflictingPorts []core.PortInfo
			importedServices []core.ServiceDetail
			importedNSE      []core.NSEFinding
		)

		var targetIPs []string
		seenIPs := make(map[string]bool)
		hostMap := make(map[string]string)
		for _, h := range hosts {
			if !seenIPs[h.IP] {
				seenIPs[h.IP] = true
				targetIPs = append(targetIPs, h.IP)
			}
			if h.Hostname != "" {
				hostMap[h.IP] = h.Hostname
			}
		}

		if nmapXMLFlag != "" {
			// Seviye 1: Nmap XML İçe Aktarma
			core.LogInfo("Seviye 1 İçe Aktarma: Nmap XML dosyası okunuyor (%s)...", nmapXMLFlag)
			impHosts, impPorts, impServices, impNSE, err := modules.LoadNmapXMLFile(nmapXMLFlag)
			if err != nil {
				core.LogError("Nmap XML dosyası yüklenemedi: %v", err)
			} else {
				if len(impHosts) > 0 {
					hosts = impHosts
				}
				openPorts = impPorts
				importedServices = impServices
				importedNSE = impNSE
				core.LogSuccess("Nmap XML başarıyla içe aktarıldı: %d host, %d açık port, %d servis, %d NSE bulgusu.",
					len(hosts), len(openPorts), len(importedServices), len(importedNSE))
			}
		} else if masscanJSONFlag != "" {
			// Seviye 1: Masscan JSON İçe Aktarma & Doğrulama
			core.LogInfo("Seviye 1 İçe Aktarma: Masscan JSON dosyası okunuyor (%s)...", masscanJSONFlag)
			impHosts, impPorts, err := modules.LoadMasscanJSONFile(masscanJSONFlag)
			if err != nil {
				core.LogError("Masscan JSON dosyası yüklenemedi: %v", err)
			} else {
				if len(impHosts) > 0 {
					hosts = impHosts
				}
				openPorts, conflictingPorts = modules.VerifyPortsWithHandshake(impPorts, threadsFlag, 1500*time.Millisecond)
			}
		} else if useMasscanFlag {
			// Seviye 2: Masscan Subprocess Taraması
			mHosts, mPorts, mErr := modules.RunMasscanSubprocess(target, portsFlag, 10000, 2*time.Minute)
			if mErr != nil {
				core.LogWarning("Masscan çalıştırılamadı (%v). Native Go port tarayıcısına geçiliyor...", mErr)
				parsedPorts := modules.ParsePortSpecs(portsFlag)
				openPorts, _ = modules.ScanMultipleHosts(targetIPs, parsedPorts, threadsFlag, 1500*time.Millisecond, fmt.Sprintf("%s/ports.json", outputDirFlag))
			} else {
				if len(mHosts) > 0 {
					hosts = mHosts
				}
				openPorts, conflictingPorts = modules.VerifyPortsWithHandshake(mPorts, threadsFlag, 1500*time.Millisecond)
			}
		} else {
			// Varsayılan: Native Go Worker Pool Port Scanner
			parsedPorts := modules.ParsePortSpecs(portsFlag)
			scanConcurrency := threadsFlag
			if len(targetIPs) > 1 && scanConcurrency > 25 {
				scanConcurrency = 20
			} else if scanConcurrency > 35 {
				scanConcurrency = 25
			}
			openPorts, _ = modules.ScanMultipleHosts(targetIPs, parsedPorts, scanConcurrency, 2500*time.Millisecond, fmt.Sprintf("%s/ports.json", outputDirFlag))
		}

		if len(openPorts) == 0 {
			core.LogWarning("Taranan port aralığında ('%s') açık port tespit edilemedi.", portsFlag)
			core.LogInfo("İpucu: Güvenlik duvarı filtrelemesi olabilir. Daha geniş aralık için '-p top-1000' veya stealth tarama için '--profile stealth -d 50' kullanabilirsiniz.")
			earlyDuration := time.Since(startTime).Seconds()
			report := modules.BuildCompleteReport(target, dnsFindings, hosts, nil, nil, nil, earlyDuration, nil, conflictingPorts)
			report.ScanProfile = profile
			_, _ = modules.GenerateHTMLReport(report, "", fmt.Sprintf("%s/report.html", outputDirFlag))
			_ = core.SaveSummaryTxt(target, hosts, nil, nil, nil, earlyDuration, fmt.Sprintf("%s/summary.txt", outputDirFlag))
			core.PrintSummaryTable(report)
			return
		}

		// Attach Hostnames to openPorts for SNI & Host Header precision
		for i := range openPorts {
			if hn, ok := hostMap[openPorts[i].IP]; ok && hn != "" {
				openPorts[i].Hostname = hn
			} else if modules.IsDomainName(target) {
				openPorts[i].Hostname = target
			}
		}
		core.PrintPortsTable(openPorts)

		// Step 3: Banner Grabbing & Service Detection
		var services []core.ServiceDetail
		if len(importedServices) > 0 {
			services = importedServices
		} else {
			core.LogStep("Adım 3: Banner Grabbing & Versiyon Tespiti")
			services, _ = modules.GrabBannersAndServices(openPorts, min(30, threadsFlag), 3500*time.Millisecond, fmt.Sprintf("%s/services.json", outputDirFlag))
		}
		core.PrintServicesTable(services)

		// Step 3.5: Nmap NSE Vulnerability Auditing (Level 3 Integration)
		var nseFindings []core.NSEFinding
		if len(importedNSE) > 0 {
			nseFindings = importedNSE
		}
		if useNmapNSEFlag && len(openPorts) > 0 {
			core.LogStep("Adım 3.5: Nmap NSE Zafiyet Taraması")
			nseMappings := modules.LoadNSEMappings("config.yaml")

			portScriptMap := make(map[int][]string)
			for _, s := range services {
				scrs := modules.GetNSEScriptsForPortAndService(s.Port, s.ServiceName, nseMappings)
				if len(scrs) > 0 {
					portScriptMap[s.Port] = append(portScriptMap[s.Port], scrs...)
				}
			}

			var targetPortNums []int
			var allScriptsToRun []string
			scriptSet := make(map[string]bool)

			for p, scrs := range portScriptMap {
				targetPortNums = append(targetPortNums, p)
				for _, sc := range scrs {
					if !scriptSet[sc] {
						scriptSet[sc] = true
						allScriptsToRun = append(allScriptsToRun, sc)
					}
				}
			}

			if len(targetPortNums) > 0 && len(allScriptsToRun) > 0 {
				liveNSE, nseErr := modules.RunNmapNSESubprocess(target, targetPortNums, allScriptsToRun, 3*time.Minute)
				if nseErr != nil {
					core.LogWarning("Nmap NSE çalıştırılamadı: %v", nseErr)
				} else {
					nseFindings = append(nseFindings, liveNSE...)
				}
			}
		}
		if len(nseFindings) > 0 {
			core.PrintNSETable(nseFindings)
		}

		// --- GENİŞLETİLMİŞ PASİF MODÜLLER (--extended) ---
		var sslFindings []core.SslFinding
		var httpAuditFindings []core.HttpAuditFinding
		var sshFindings []core.SshAuditFinding

		if extendedFlag {
			core.LogStep("Genişletilmiş Modül: SSL/TLS Sertifika & Protokol Denetimi")
			sslFindings, _ = modules.AuditSSLMultiple(services, 4*time.Second, fmt.Sprintf("%s/ssl_findings.json", outputDirFlag))
			core.PrintSslTable(sslFindings)

			core.LogStep("Genişletilmiş Modül: HTTP Güvenlik Denetimi (Headers, CORS, Methods)")
			httpAuditFindings, _ = modules.AuditHTTPMultiple(services, 5*time.Second, fmt.Sprintf("%s/http_audit.json", outputDirFlag))
			core.PrintHttpAuditTable(httpAuditFindings)

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
				min(25, threadsFlag),
				delayFlag,
				fmt.Sprintf("%s/dirs.json", outputDirFlag),
				fmt.Sprintf("%s/findings.txt", outputDirFlag),
			)
			core.PrintDirFindingsTable(dirFindings)
		}

		// Step 5: Reporting
		core.LogStep("Adım 5: Raporlama")
		duration := time.Since(startTime).Seconds()
		report := modules.BuildCompleteReport(target, dnsFindings, hosts, openPorts, services, dirFindings, duration, nseFindings, conflictingPorts)
		report.ScanProfile = profile

		// Attach extended findings
		report.SslFindings = sslFindings
		report.HttpAuditFindings = httpAuditFindings
		report.SshAuditFindings = sshFindings

		_, _ = modules.GenerateHTMLReport(report, "", fmt.Sprintf("%s/report.html", outputDirFlag))

		// summary.txt
		summaryPath := fmt.Sprintf("%s/summary.txt", outputDirFlag)
		if err := core.SaveSummaryTxt(
			target, hosts, openPorts, services, dirFindings, duration, summaryPath,
			sslFindings, httpAuditFindings, sshFindings, nseFindings,
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
	scanCmd.Flags().StringVar(&profileFlag, "profile", "balanced", "Tarama profili: 'aggressive' (Masscan+NSE), 'balanced' (Varsayılan), 'stealth' (Sessiz)")
	scanCmd.Flags().StringVar(&nmapXMLFlag, "nmap-xml", "", "İçe aktarılacak Nmap XML çıktı dosyası (-oX)")
	scanCmd.Flags().StringVar(&masscanJSONFlag, "masscan-json", "", "İçe aktarılacak Masscan JSON çıktı dosyası (-oJ)")
	scanCmd.Flags().BoolVar(&useMasscanFlag, "use-masscan", false, "Masscan ile port taraması çalıştırır (Root/Admin gerektirir)")
	scanCmd.Flags().BoolVar(&useNmapNSEFlag, "use-nmap-nse", false, "Tespit edilen servislere özel Nmap NSE zafiyet scriptlerini çalıştırır")

	RootCmd.AddCommand(scanCmd)
}


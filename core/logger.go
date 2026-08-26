package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pterm/pterm"
)

const DefaultAuditLogPath = "output/audit.log"

// LogAudit writes an audit log line with timestamp and action to audit.log.
func LogAudit(action, target, details, status string) {
	if status == "" {
		status = "SUCCESS"
	}
	dir := filepath.Dir(DefaultAuditLogPath)
	_ = os.MkdirAll(dir, 0755)

	f, err := os.OpenFile(DefaultAuditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	entry := fmt.Sprintf("%s [INFO] ACTION=%s | TARGET=%s | STATUS=%s | DETAILS=%s\n",
		timestamp, action, target, status, details)
	_, _ = f.WriteString(entry)
}

// PrintBanner displays the ASCII banner.
func PrintBanner(version string) {
	bannerText := `
  ____                  _             ____                     
 / ___| _ __   ___  ___| |_ ___ _ __ |  _ \ ___  ___ ___  _ __ 
 \___ \| '_ \ / _ \/ __| __/ _ \ '__|| |_) / _ \/ __/ _ \| '_ \ 
  ___) | |_) |  __/ (__| ||  __/ |   |  _ <  __/ (_| (_) | | | |
 |____/| .__/ \___|\___|\__\___|_|   |_| \_\___|\___\___/|_| |_|
       |_|                                                     
   -- Fast, Modular Network Recon & Vulnerability Scanner v` + version + ` --
                 Yetkilendirilmis Guvenlik ve Lab Test Platformu`

	pterm.DefaultBox.WithTitle("SPECTERRECON").WithTitleTopCenter().
		WithBoxStyle(pterm.NewStyle(pterm.FgLightCyan)).
		Println(strings.TrimSpace(bannerText))
}

// LogStep prints step header.
func LogStep(stepName string) {
	pterm.Println()
	pterm.DefaultSection.WithStyle(pterm.NewStyle(pterm.FgMagenta, pterm.Bold)).
		Println(fmt.Sprintf("========= [ %s ] =========", strings.ToUpper(stepName)))
}

// LogInfo prints informational message.
func LogInfo(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	pterm.Info.Println(msg)
}

// LogSuccess prints success message.
func LogSuccess(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	pterm.Success.Println(msg)
}

// LogWarning prints warning message.
func LogWarning(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	pterm.Warning.Println(msg)
}

// LogError prints error message.
func LogError(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	pterm.Error.Println(msg)
}

// PrintDNSTable prints DNS enumeration and subdomain findings in a clean PTerm table.
func PrintDNSTable(findings []DNSFinding) {
	if len(findings) == 0 {
		return
	}
	tableData := pterm.TableData{
		{"Hostname / FQDN", "IP Adresi", "Kayıt Tipi", "Kaynak"},
	}
	for _, f := range findings {
		src := "A/AAAA Çözümleme"
		if f.Source == "subdomain_bruteforce" {
			src = "🔍 Subdomain Brute-Force"
		}
		tableData = append(tableData, []string{
			f.Hostname,
			f.IP,
			f.RecordType,
			src,
		})
	}
	pterm.Println()
	_ = pterm.DefaultTable.WithHasHeader().WithBoxed().WithHeaderStyle(pterm.NewStyle(pterm.FgLightMagenta, pterm.Bold)).
		WithData(tableData).Render()
}

// PrintHostsTable prints discovered hosts in a clean PTerm table.
func PrintHostsTable(hosts []HostInfo) {
	if len(hosts) == 0 {
		return
	}
	tableData := pterm.TableData{
		{"IP Adresi", "MAC Adresi", "Yöntem", "Gecikme (Latency)", "Durum"},
	}
	for _, h := range hosts {
		mac := h.MAC
		if mac == "" {
			mac = "-"
		}
		lat := "-"
		if h.LatencyMs != nil {
			lat = fmt.Sprintf("%.2f ms", *h.LatencyMs)
		}
		tableData = append(tableData, []string{
			h.IP,
			mac,
			h.DiscoveryMethod,
			lat,
			strings.ToUpper(h.State),
		})
	}
	pterm.Println()
	_ = pterm.DefaultTable.WithHasHeader().WithBoxed().WithHeaderStyle(pterm.NewStyle(pterm.FgLightCyan, pterm.Bold)).
		WithData(tableData).Render()
}

// PrintPortsTable prints open ports in a clean PTerm table.
func PrintPortsTable(ports []PortInfo) {
	if len(ports) == 0 {
		return
	}
	tableData := pterm.TableData{
		{"IP Adresi", "Port/Protokol", "Servis", "Durum", "Yanıt Süresi"},
	}
	for _, p := range ports {
		resp := "-"
		if p.ResponseTimeMs != nil {
			resp = fmt.Sprintf("%.2f ms", *p.ResponseTimeMs)
		}
		service := p.ServiceName
		if service == "" {
			service = "unknown"
		}
		tableData = append(tableData, []string{
			p.IP,
			fmt.Sprintf("%d/%s", p.Port, strings.ToUpper(p.Protocol)),
			service,
			strings.ToUpper(p.State),
			resp,
		})
	}
	pterm.Println()
	_ = pterm.DefaultTable.WithHasHeader().WithBoxed().WithHeaderStyle(pterm.NewStyle(pterm.FgLightBlue, pterm.Bold)).
		WithData(tableData).Render()
}

// PrintServicesTable prints detected services & banners in a clean PTerm table.
func PrintServicesTable(services []ServiceDetail) {
	if len(services) == 0 {
		return
	}
	tableData := pterm.TableData{
		{"Hedef", "Servis", "Versiyon / Başlık", "Açıklama / Banner", "SSL"},
	}
	for _, s := range services {
		ver := s.ServiceVersion
		if ver == "" {
			ver = s.HTTPTitle
		}
		if ver == "" {
			ver = "-"
		}

		banner := s.BannerRaw
		if len(banner) > 40 {
			banner = banner[:37] + "..."
		}
		if banner == "" {
			banner = s.ServiceDescription
		}
		if banner == "" {
			banner = "-"
		}

		sslStr := "Hayır"
		if s.SSLEnabled {
			sslStr = "🔒 Evet"
		}

		tableData = append(tableData, []string{
			fmt.Sprintf("%s:%d", s.IP, s.Port),
			strings.ToUpper(s.ServiceName),
			ver,
			banner,
			sslStr,
		})
	}
	pterm.Println()
	_ = pterm.DefaultTable.WithHasHeader().WithBoxed().WithHeaderStyle(pterm.NewStyle(pterm.FgGreen, pterm.Bold)).
		WithData(tableData).Render()
}

// PrintVulnsTable prints detected CVE vulnerabilities in a clean PTerm table.
func PrintVulnsTable(vulns []VulnerabilityInfo) {
	if len(vulns) == 0 {
		pterm.Success.Println("Taranan servislerde bilinen kritik CVE zafiyeti bulunamadı.")
		return
	}
	tableData := pterm.TableData{
		{"CVE ID", "CVSS", "Şiddet", "Etkilenen Servis", "Zafiyet Açıklaması"},
	}
	for _, v := range vulns {
		desc := v.Description
		if len(desc) > 65 {
			desc = desc[:62] + "..."
		}
		tableData = append(tableData, []string{
			v.CVEID,
			fmt.Sprintf("%.1f", v.CVSSScore),
			v.Severity,
			v.AffectedService,
			desc,
		})
	}
	pterm.Println()
	_ = pterm.DefaultTable.WithHasHeader().WithBoxed().WithHeaderStyle(pterm.NewStyle(pterm.FgRed, pterm.Bold)).
		WithData(tableData).Render()
}

// PrintDirFindingsTable prints web fuzzing directory findings in a clean PTerm table.
func PrintDirFindingsTable(findings []DirFuzzFinding) {
	if len(findings) == 0 {
		return
	}
	tableData := pterm.TableData{
		{"Durum Kodu", "URL / Yol", "Boyut", "Başlık / Yönlendirme", "Kritiklik / Eşleşme"},
	}
	for _, f := range findings {
		info := f.Title
		if info == "" && f.RedirectLocation != "" {
			info = "➜ " + f.RedirectLocation
		}
		if info == "" {
			info = "-"
		}
		if len(info) > 35 {
			info = info[:32] + "..."
		}

		tag := "Standart"
		if f.IsSensitive {
			tag = "⚠️ HASSAS DOSYA"
		} else if f.WordlistMatched != "" {
			tag = fmt.Sprintf("📁 %s", f.WordlistMatched)
		}

		tableData = append(tableData, []string{
			strconv.Itoa(f.StatusCode),
			f.URL,
			fmt.Sprintf("%d B", f.ContentLength),
			info,
			tag,
		})
	}
	pterm.Println()
	_ = pterm.DefaultTable.WithHasHeader().WithBoxed().WithHeaderStyle(pterm.NewStyle(pterm.FgYellow, pterm.Bold)).
		WithData(tableData).Render()
}

// PrintSummaryTable displays final executive scan summary.
func PrintSummaryTable(report CompleteScanReport) {
	pterm.Println()
	tableData := pterm.TableData{
		{"Metrik", "Değer"},
		{"Taranan Hedef", report.Target},
	}
	if report.TotalDNSRecords > 0 {
		tableData = append(tableData, []string{"Çözümlenen DNS Kayıtları", strconv.Itoa(report.TotalDNSRecords)})
	}
	tableData = append(tableData, [][]string{
		{"Keşfedilen Hostlar", strconv.Itoa(report.TotalHosts)},
		{"Açık Portlar", strconv.Itoa(report.TotalOpenPorts)},
		{"Tespit Edilen Zafiyetler", strconv.Itoa(report.TotalVulns)},
		{"Web Dizin Bulguları", strconv.Itoa(report.TotalFindings)},
		{"Toplam Süre", fmt.Sprintf("%.2f saniye", report.DurationSeconds)},
		{"Özet Dosyası (TXT)", "output/summary.txt"},
		{"HTML Rapor Dosyası", "output/report.html"},
	}...)

	_ = pterm.DefaultTable.WithHasHeader().WithBoxed().WithHeaderStyle(pterm.NewStyle(pterm.FgCyan, pterm.Bold)).
		WithData(tableData).Render()
}


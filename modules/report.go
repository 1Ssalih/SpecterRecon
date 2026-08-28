package modules

import (
	"crypto/rand"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/templates"
)

// BuildCompleteReport combines individual artifacts into a unified CompleteScanReport.
func BuildCompleteReport(
	target string,
	dnsFindings []core.DNSFinding,
	hosts []core.HostInfo,
	ports []core.PortInfo,
	services []core.ServiceDetail,
	findings []core.DirFuzzFinding,
	durationSeconds float64,
	extra ...interface{},
) core.CompleteScanReport {
	var (
		nseFindings      []core.NSEFinding
		conflictingPorts []core.PortInfo
	)

	for _, ex := range extra {
		switch v := ex.(type) {
		case []core.NSEFinding:
			nseFindings = v
		case []core.PortInfo:
			conflictingPorts = v
		}
	}

	if len(hosts) == 0 && len(ports) > 0 {
		seenIPs := make(map[string]bool)
		for _, p := range ports {
			if !seenIPs[p.IP] {
				seenIPs[p.IP] = true
				hosts = append(hosts, core.NewHostInfo(p.IP, "direct"))
			}
		}
	}

	var hostReports []core.HostScanReport
	for _, h := range hosts {
		var hPorts []core.PortInfo
		for _, p := range ports {
			if p.IP == h.IP {
				hPorts = append(hPorts, p)
			}
		}

		var hServices []core.ServiceDetail
		for _, s := range services {
			if s.IP == h.IP {
				hServices = append(hServices, s)
			}
		}

		var hFindings []core.DirFuzzFinding
		for _, f := range findings {
			if strings.Contains(f.URL, h.IP) {
				hFindings = append(hFindings, f)
			}
		}

		var hNSE []core.NSEFinding
		for _, nse := range nseFindings {
			if nse.Host == h.IP || strings.Contains(nse.Host, h.IP) {
				hNSE = append(hNSE, nse)
			}
		}

		var hConflicts []core.PortInfo
		for _, cp := range conflictingPorts {
			if cp.IP == h.IP {
				hConflicts = append(hConflicts, cp)
			}
		}

		hostReports = append(hostReports, core.HostScanReport{
			Host:             h,
			Ports:            hPorts,
			Services:         hServices,
			DirFindings:      hFindings,
			NSEFindings:      hNSE,
			ConflictingPorts: hConflicts,
		})
	}

	randomID := make([]byte, 4)
	_, _ = rand.Read(randomID)

	return core.CompleteScanReport{
		ScanID:           fmt.Sprintf("%x", randomID),
		Target:           target,
		ScanDate:         time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		DurationSeconds:  durationSeconds,
		DNSFindings:      dnsFindings,
		TotalDNSRecords:  len(dnsFindings),
		Hosts:            hostReports,
		TotalHosts:       len(hostReports),
		TotalOpenPorts:   len(ports),
		TotalFindings:    len(findings),
		NSEFindings:      nseFindings,
		ConflictingPorts: conflictingPorts,
	}
}

// GenerateHTMLReport renders the HTML template and writes output/report.html.
// It supports both external custom template files and embedded standalone templates.
func GenerateHTMLReport(report core.CompleteScanReport, templatePath, outputPath string) (string, error) {
	if templatePath == "" {
		templatePath = "templates/report.html.tmpl"
	}
	if outputPath == "" {
		outputPath = "output/report.html"
	}

	core.LogInfo("HTML Raporu üretiliyor: '%s'...", outputPath)
	core.LogAudit("REPORT_GENERATION_START", report.Target, fmt.Sprintf("output=%s", outputPath), "SUCCESS")

	var tmpl *template.Template
	var err error

	if templatePath != "" && templatePath != "templates/report.html.tmpl" {
		tmpl, err = template.ParseFiles(templatePath)
		if err != nil {
			core.LogError("Belirtilen rapor şablonu okunamadı (%s): %v", templatePath, err)
			return "", err
		}
	} else {
		// 1. First check if external template exists in current directory
		if _, statErr := os.Stat("templates/report.html.tmpl"); statErr == nil {
			tmpl, err = template.ParseFiles("templates/report.html.tmpl")
		}
		// 2. Fall back to embedded template (100% standalone, no file dependency)
		if tmpl == nil || err != nil {
			tmpl, err = template.New("report.html.tmpl").Parse(templates.DefaultHTMLReportTemplate)
			if err != nil {
				core.LogError("Gömülü rapor şablonu yüklenemedi: %v", err)
				return "", err
			}
		}
	}

	dir := filepath.Dir(outputPath)
	_ = os.MkdirAll(dir, 0755)

	outFile, err := os.Create(outputPath)
	if err != nil {
		core.LogError("Rapor dosyası oluşturulamadı: %v", err)
		return "", err
	}
	defer outFile.Close()

	if err := tmpl.Execute(outFile, report); err != nil {
		core.LogError("Rapor render hatası: %v", err)
		return "", err
	}

	core.LogSuccess("HTML Raporu başarıyla oluşturuldu: %s", outputPath)
	core.LogAudit("REPORT_GENERATION_COMPLETE", report.Target, fmt.Sprintf("output=%s", outputPath), "SUCCESS")

	return outputPath, nil
}

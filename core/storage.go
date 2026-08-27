package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// EnsureOutputDir ensures that the output directory exists.
func EnsureOutputDir(dir string) string {
	if dir == "" {
		dir = "output"
	}
	_ = os.MkdirAll(dir, 0755)
	return dir
}

// SaveJSON marshals and writes any data struct as indented JSON.
func SaveJSON(data interface{}, path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON marshal hatası: %w", err)
	}

	return os.WriteFile(path, bytes, 0644)
}

// LoadJSON reads and unmarshals JSON into the target struct.
func LoadJSON(path string, target interface{}) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("JSON okuma hatası (%s): %w", path, err)
	}

	if len(bytes) == 0 {
		return nil
	}

	return json.Unmarshal(bytes, target)
}

// SaveIPList writes DNS findings to JSON (output/ip_list.json).
func SaveIPList(findings []DNSFinding, path string) error {
	if path == "" {
		path = "output/ip_list.json"
	}
	return SaveJSON(findings, path)
}

// LoadIPList reads DNS findings from JSON.
func LoadIPList(path string) ([]DNSFinding, error) {
	if path == "" {
		path = "output/ip_list.json"
	}
	var findings []DNSFinding
	err := LoadJSON(path, &findings)
	return findings, err
}

// SaveHosts writes hosts slice to JSON.
func SaveHosts(hosts []HostInfo, path string) error {
	if path == "" {
		path = "output/hosts.json"
	}
	return SaveJSON(hosts, path)
}

// LoadHosts reads hosts slice from JSON.
func LoadHosts(path string) ([]HostInfo, error) {
	if path == "" {
		path = "output/hosts.json"
	}
	var hosts []HostInfo
	err := LoadJSON(path, &hosts)
	return hosts, err
}

// SavePorts writes ports slice to JSON.
func SavePorts(ports []PortInfo, path string) error {
	if path == "" {
		path = "output/ports.json"
	}
	return SaveJSON(ports, path)
}

// LoadPorts reads ports slice from JSON.
func LoadPorts(path string) ([]PortInfo, error) {
	if path == "" {
		path = "output/ports.json"
	}
	var ports []PortInfo
	err := LoadJSON(path, &ports)
	return ports, err
}

// SaveServices writes services slice to JSON.
func SaveServices(services []ServiceDetail, path string) error {
	if path == "" {
		path = "output/services.json"
	}
	return SaveJSON(services, path)
}

// LoadServices reads services slice from JSON.
func LoadServices(path string) ([]ServiceDetail, error) {
	if path == "" {
		path = "output/services.json"
	}
	var services []ServiceDetail
	err := LoadJSON(path, &services)
	return services, err
}

// SaveFindings writes findings to JSON and plain text.
func SaveFindings(findings []DirFuzzFinding, jsonPath, txtPath string) error {
	if jsonPath == "" {
		jsonPath = "output/dirs.json"
	}
	if err := SaveJSON(findings, jsonPath); err != nil {
		return err
	}

	if txtPath != "" {
		dir := filepath.Dir(txtPath)
		if dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0755)
		}
		file, err := os.Create(txtPath)
		if err != nil {
			return err
		}
		defer file.Close()

		for _, item := range findings {
			matchedTag := item.MatchedTech
			if matchedTag == "" {
				matchedTag = item.WordlistMatched
			}
			matched := ""
			if matchedTag != "" {
				matched = fmt.Sprintf(" [Match: %s]", matchedTag)
			}
			sensitive := ""
			if item.IsSensitive {
				if item.StatusCode == 401 || item.StatusCode == 403 {
					sensitive = " [CRITICAL SENSITIVE: Potential Sensitive File (Access Denied)]"
				} else {
					sensitive = " [CRITICAL SENSITIVE]"
				}
			}
			_, _ = fmt.Fprintf(file, "[%d] %s (size: %d bytes)%s%s\n", item.StatusCode, item.URL, item.ContentLength, matched, sensitive)
		}
	}
	return nil
}

// SaveSslFindings writes SSL findings to JSON.
func SaveSslFindings(findings []SslFinding, path string) error {
	if path == "" {
		path = "output/ssl_findings.json"
	}
	return SaveJSON(findings, path)
}

// SaveHttpAuditFindings writes HTTP audit findings to JSON.
func SaveHttpAuditFindings(findings []HttpAuditFinding, path string) error {
	if path == "" {
		path = "output/http_audit.json"
	}
	return SaveJSON(findings, path)
}

// SaveSshAuditFindings writes SSH audit findings to JSON.
func SaveSshAuditFindings(findings []SshAuditFinding, path string) error {
	if path == "" {
		path = "output/ssh_audit.json"
	}
	return SaveJSON(findings, path)
}

// SaveSummaryTxt writes a single human-readable summary of all scan results to a .txt file.
func SaveSummaryTxt(
	target string,
	hosts []HostInfo,
	ports []PortInfo,
	services []ServiceDetail,
	findings []DirFuzzFinding,
	durationSec float64,
	outPath string,
	opts ...interface{},
) error {
	if outPath == "" {
		outPath = "output/summary.txt"
	}
	dir := filepath.Dir(outPath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("summary.txt oluşturulamadı: %w", err)
	}
	defer f.Close()

	w := func(format string, a ...interface{}) {
		_, _ = fmt.Fprintf(f, format+"\n", a...)
	}

	w("=== SpecterRecon Tarama Özeti ===")
	w("Hedef : %s", target)
	w("Tarih : %s", time.Now().Format("2006-01-02 15:04:05"))
	w("Süre  : %.2f saniye", durationSec)
	w("")

	// Hostlar
	w("[HOSTLAR] (%d)", len(hosts))
	if len(hosts) == 0 {
		w("  (tespit edilemedi)")
	}
	for _, h := range hosts {
		hostname := ""
		if h.Hostname != "" {
			hostname = " (" + h.Hostname + ")"
		}
		w("  + %s%s [%s, %s]", h.IP, hostname, h.DiscoveryMethod, h.State)
	}
	w("")

	// Açık Portlar
	w("[AÇIK PORTLAR] (%d)", len(ports))
	if len(ports) == 0 {
		w("  (tespit edilemedi)")
	}
	for _, p := range ports {
		svc := p.ServiceName
		if svc == "" {
			svc = "unknown"
		}
		w("  + %s:%-5d  %-15s [%s]", p.IP, p.Port, svc, p.State)
	}
	w("")

	// Servisler & Versiyon
	w("[SERVİSLER & VERSİYON] (%d)", len(services))
	if len(services) == 0 {
		w("  (tespit edilemedi)")
	}
	for _, s := range services {
		ver := s.ServiceVersion
		if ver == "" {
			ver = s.HTTPTitle
		}
		if ver == "" {
			ver = "-"
		}
		ssl := ""
		if s.SSLEnabled {
			ssl = " [SSL]"
		}
		confStr := ""
		if s.VersionConfidence > 0 {
			confStr = fmt.Sprintf(" (Güven: %%%d, Kaynak: %s)", s.VersionConfidence, s.VersionSource)
		}
		w("  + %s:%d  %-10s  %s%s%s", s.IP, s.Port, s.ServiceName, ver, ssl, confStr)
	}
	w("")

	// Web Dizin Bulguları
	w("[WEB BULGULARI] (%d)", len(findings))
	if len(findings) == 0 {
		w("  (dizin bulgusu yok)")
	}
	for _, fi := range findings {
		tag := ""
		if fi.IsSensitive {
			tag = " [KRİTİK DOSYA]"
		}
		w("  + [%d] %s (%d B)%s", fi.StatusCode, fi.URL, fi.ContentLength, tag)
	}
	w("")

	// opts içindeki ek modül bulgularını yaz (pasif genişletilmiş modüller)
	for _, opt := range opts {
		switch v := opt.(type) {
		case []SslFinding:
			if len(v) > 0 {
				w("[SSL/TLS BULGULARI] (%d)", len(v))
				for _, s := range v {
					for _, note := range s.Notes {
						w("  !! %s:%d — %s", s.IP, s.Port, note)
					}
				}
				w("")
			}
		case []HttpAuditFinding:
			if len(v) > 0 {
				w("[WEB GÜVENLİK DENETİMİ] (%d)", len(v))
				for _, h := range v {
					for _, m := range h.MissingHeaders {
						w("  !! %s — EKSİK HEADER: %s", h.URL, m)
					}
					for _, m := range h.DangerousMethods {
						w("  !! %s — TEHLİKELİ HTTP METOD: %s", h.URL, m)
					}
					for _, c := range h.CORSIssues {
						w("  !! %s — CORS SORUNU: %s", h.URL, c)
					}
					if h.GraphQLOpen {
						w("  !! %s — GraphQL introspection AÇIK", h.URL)
					}
				}
				w("")
			}
		case []SshAuditFinding:
			if len(v) > 0 {
				w("[SSH DENETİMİ] (%d)", len(v))
				for _, s := range v {
					if s.RootLoginOn {
						w("  !! %s:%d — ROOT GİRİŞİ AÇIK", s.IP, s.Port)
					}
					if s.PasswordAuthOn {
						w("  !! %s:%d — PAROLA TABANLI KİMLİK DOĞRULAMA AKTİF", s.IP, s.Port)
					}
					for _, alg := range s.WeakAlgorithms {
						w("  !! %s:%d — ZAYIF ALGORİTMA: %s", s.IP, s.Port, alg)
					}
				}
				w("")
			}
		}
	}

	// Özet sayaçları
	sensitiveCount := 0
	for _, fi := range findings {
		if fi.IsSensitive {
			sensitiveCount++
		}
	}

	w("=== ÖZET ===")
	w("  Hostlar        : %d", len(hosts))
	w("  Açık Portlar   : %d", len(ports))
	w("  Web Bulguları  : %d toplam (%d hassas dosya)", len(findings), sensitiveCount)
	w("  Rapor          : output/report.html")
	w("  Süre           : %.2f saniye", durationSec)

	return nil
}

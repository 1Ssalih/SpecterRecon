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

// SaveVulns writes vulnerabilities slice to JSON.
func SaveVulns(vulns []VulnerabilityInfo, path string) error {
	if path == "" {
		path = "output/vulns.json"
	}
	return SaveJSON(vulns, path)
}

// LoadVulns reads vulnerabilities slice from JSON.
func LoadVulns(path string) ([]VulnerabilityInfo, error) {
	if path == "" {
		path = "output/vulns.json"
	}
	var vulns []VulnerabilityInfo
	err := LoadJSON(path, &vulns)
	return vulns, err
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
			matched := ""
			if item.WordlistMatched != "" {
				matched = fmt.Sprintf(" [Match: %s]", item.WordlistMatched)
			}
			sensitive := ""
			if item.IsSensitive {
				sensitive = " [CRITICAL SENSITIVE]"
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

// SaveSmbFindings writes SMB findings to JSON.
func SaveSmbFindings(findings []SmbFinding, path string) error {
	if path == "" {
		path = "output/smb_findings.json"
	}
	return SaveJSON(findings, path)
}

// SaveFtpFindings writes FTP findings to JSON.
func SaveFtpFindings(findings []FtpFinding, path string) error {
	if path == "" {
		path = "output/ftp_findings.json"
	}
	return SaveJSON(findings, path)
}

// SaveSmtpFindings writes SMTP findings to JSON.
func SaveSmtpFindings(findings []SmtpFinding, path string) error {
	if path == "" {
		path = "output/smtp_findings.json"
	}
	return SaveJSON(findings, path)
}

// SaveSnmpFindings writes SNMP findings to JSON.
func SaveSnmpFindings(findings []SnmpFinding, path string) error {
	if path == "" {
		path = "output/snmp_findings.json"
	}
	return SaveJSON(findings, path)
}

// SaveDbFindings writes database findings to JSON.
func SaveDbFindings(findings []DbFinding, path string) error {
	if path == "" {
		path = "output/db_findings.json"
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

// SaveCredFindings writes credential findings to JSON.
func SaveCredFindings(findings []CredFinding, path string) error {
	if path == "" {
		path = "output/creds_found.json"
	}
	return SaveJSON(findings, path)
}

// SaveContainerFindings writes container/cloud findings to JSON.
func SaveContainerFindings(findings []ContainerFinding, path string) error {
	if path == "" {
		path = "output/container_findings.json"
	}
	return SaveJSON(findings, path)
}

// SaveLdapFindings writes LDAP findings to JSON.
func SaveLdapFindings(findings []LdapFinding, path string) error {
	if path == "" {
		path = "output/ldap_findings.json"
	}
	return SaveJSON(findings, path)
}

// SaveSummaryTxt writes a single human-readable summary of all scan results to a .txt file.
func SaveSummaryTxt(
	target string,
	hosts []HostInfo,
	ports []PortInfo,
	services []ServiceDetail,
	vulns []VulnerabilityInfo,
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
		w("  + %s:%d  %-10s  %s%s", s.IP, s.Port, s.ServiceName, ver, ssl)
	}
	w("")

	// Zafiyetler
	w("[ZAFİYETLER] (%d)", len(vulns))
	if len(vulns) == 0 {
		w("  (kritik zafiyet bulunamadı)")
	}
	for _, v := range vulns {
		w("  !! [%s / CVSS:%.1f] %s -> %s", v.Severity, v.CVSSScore, v.CVEID, v.AffectedService)
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

	// opts içindeki ek modül bulgularını yaz
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
		case []SmbFinding:
			if len(v) > 0 {
				w("[SMB BULGULARI] (%d)", len(v))
				for _, s := range v {
					if s.NullSession {
						w("  !! %s:%d — NULL SESSION AKTİF", s.IP, s.Port)
					}
					if s.SigningDisabled {
						w("  !! %s:%d — SMB SIGNING DEVRE DIŞI (relay riski)", s.IP, s.Port)
					}
					if s.SMBv1Enabled {
						w("  !! %s:%d — SMBv1 AKTİF (EternalBlue riski)", s.IP, s.Port)
					}
					for _, share := range s.Shares {
						w("  + %s — Paylaşım: %s", s.IP, share)
					}
				}
				w("")
			}
		case []FtpFinding:
			if len(v) > 0 {
				w("[FTP BULGULARI] (%d)", len(v))
				for _, f := range v {
					if f.AnonLogin {
						w("  !! %s:%d — ANONYMOUS FTP GİRİŞİ MÜMKÜN", f.IP, f.Port)
					}
					if f.AnonWritable {
						w("  !! %s:%d — ANONYMOUS YAZMA YETKİSİ VAR", f.IP, f.Port)
					}
					if !f.FTPSEnabled {
						w("  !! %s:%d — FTPS (TLS) DEVRE DIŞI", f.IP, f.Port)
					}
				}
				w("")
			}
		case []SmtpFinding:
			if len(v) > 0 {
				w("[SMTP BULGULARI] (%d)", len(v))
				for _, s := range v {
					if s.OpenRelay {
						w("  !! %s:%d — OPEN RELAY TESPİT EDİLDİ", s.IP, s.Port)
					}
					if s.VRFYEnabled {
						w("  !! %s:%d — VRFY KOMUTU AKTİF (kullanıcı enum)", s.IP, s.Port)
					}
				}
				w("")
			}
		case []SnmpFinding:
			if len(v) > 0 {
				w("[SNMP BULGULARI] (%d)", len(v))
				for _, s := range v {
					w("  !! %s:%d — SNMP '%s' community string ile erişildi (%s)", s.IP, s.Port, s.Community, s.Version)
					if s.SysName != "" {
						w("  +  Cihaz: %s — %s", s.SysName, s.SysDescr)
					}
				}
				w("")
			}
		case []DbFinding:
			if len(v) > 0 {
				w("[VERİTABANI BULGULARI] (%d)", len(v))
				for _, d := range v {
					if d.AnonAccess {
						w("  !! %s:%d [%s] — KİMLİK DOĞRULAMASIZ ERİŞİM MÜMKÜN", d.IP, d.Port, d.DbType)
					}
					if d.DefaultCreds {
						w("  !! %s:%d [%s] — DEFAULT KREDİ BAŞARILI: %s/%s", d.IP, d.Port, d.DbType, d.Username, d.Password)
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
		case []CredFinding:
			if len(v) > 0 {
				w("[VARSAYILAN KREDİ BULGULARI] (%d)", len(v))
				for _, c := range v {
					w("  !! %s:%d [%s] — GİRİŞ BAŞARILI: %s / %s", c.IP, c.Port, c.Protocol, c.Username, c.Password)
				}
				w("")
			}
		case []ContainerFinding:
			if len(v) > 0 {
				w("[CONTAINER/CLOUD BULGULARI] (%d)", len(v))
				for _, c := range v {
					if c.Exposed {
						w("  !! %s:%d [%s] — KİMLİK DOĞRULAMASIZ ERİŞİM AÇIK", c.IP, c.Port, c.Service)
					}
					for _, ep := range c.Endpoints {
						w("  +  Endpoint: %s", ep)
					}
				}
				w("")
			}
		case []LdapFinding:
			if len(v) > 0 {
				w("[LDAP/AD BULGULARI] (%d)", len(v))
				for _, l := range v {
					if l.AnonymousBind {
						w("  !! %s:%d — ANONIM LDAP BIND MÜMKÜN", l.IP, l.Port)
					}
					if l.DomainName != "" {
						w("  +  Domain: %s (%s)", l.DomainName, l.ServerType)
					}
				}
				w("")
			}
		}
	}

	// Özet sayaçları
	critCount := 0
	for _, v := range vulns {
		if v.Severity == "CRITICAL" || v.Severity == "HIGH" {
			critCount++
		}
	}
	sensitiveCount := 0
	for _, fi := range findings {
		if fi.IsSensitive {
			sensitiveCount++
		}
	}

	w("=== ÖZET ===")
	w("  Hostlar        : %d", len(hosts))
	w("  Açık Portlar   : %d", len(ports))
	w("  Zafiyetler     : %d toplam (%d kritik/yüksek)", len(vulns), critCount)
	w("  Web Bulguları  : %d toplam (%d hassas dosya)", len(findings), sensitiveCount)
	w("  Rapor          : output/report.html")
	w("  Süre           : %.2f saniye", durationSec)

	return nil
}



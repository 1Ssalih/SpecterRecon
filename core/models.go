package core

import "time"

// HostInfo represents a single discovered host.
type HostInfo struct {
	IP              string   `json:"ip"`
	MAC             string   `json:"mac,omitempty"`
	Vendor          string   `json:"vendor,omitempty"`
	Hostname        string   `json:"hostname,omitempty"`
	DiscoveryMethod string   `json:"discovery_method"`
	LatencyMs       *float64 `json:"latency_ms,omitempty"`
	State           string   `json:"state"`
	Timestamp       string   `json:"timestamp"`
}

// PortInfo represents an open or tested port.
type PortInfo struct {
	IP             string   `json:"ip"`
	Port           int      `json:"port"`
	Protocol       string   `json:"protocol"`
	State          string   `json:"state"`
	ServiceName    string   `json:"service_name,omitempty"`
	ResponseTimeMs *float64 `json:"response_time_ms,omitempty"`
}

// ServiceDetail represents detailed banner & version information.
type ServiceDetail struct {
	IP                 string                 `json:"ip"`
	Port               int                    `json:"port"`
	Protocol           string                 `json:"protocol"`
	ServiceName        string                 `json:"service_name"`
	ServiceDescription string                 `json:"service_description,omitempty"`
	ServiceVersion     string                 `json:"service_version,omitempty"`
	BannerRaw          string                 `json:"banner_raw,omitempty"`
	HTTPTitle          string                 `json:"http_title,omitempty"`
	HTTPServer         string                 `json:"http_server,omitempty"`
	HTTPTechnologies   []string               `json:"http_technologies"`
	SSLEnabled         bool                   `json:"ssl_enabled"`
	SSLInfo            map[string]interface{} `json:"ssl_info,omitempty"`
	State              string                 `json:"state"`
}

// VulnerabilityInfo represents a matched CVE or security advisory.
type VulnerabilityInfo struct {
	CVEID           string   `json:"cve_id"`
	CVSSScore       float64  `json:"cvss_score"`
	Severity        string   `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
	Description     string   `json:"description"`
	AffectedService string   `json:"affected_service"`
	AffectedVersion string   `json:"affected_version,omitempty"`
	PublishedDate   string   `json:"published_date,omitempty"`
	References      []string `json:"references"`
	Mitigation      string   `json:"mitigation,omitempty"`
}

// DirFuzzFinding represents an identified web path or file.
type DirFuzzFinding struct {
	URL              string   `json:"url"`
	Path             string   `json:"path"`
	StatusCode       int      `json:"status_code"`
	ContentLength    int64    `json:"content_length"`
	RedirectLocation string   `json:"redirect_location,omitempty"`
	Title            string   `json:"title,omitempty"`
	ResponseTimeMs   *float64 `json:"response_time_ms,omitempty"`
	IsSensitive      bool     `json:"is_sensitive"`
}

// HostScanReport aggregates all findings for a single host.
type HostScanReport struct {
	Host            HostInfo            `json:"host"`
	Ports           []PortInfo          `json:"ports"`
	Services        []ServiceDetail     `json:"services"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
	DirFindings     []DirFuzzFinding    `json:"dir_findings"`
}

// CompleteScanReport represents the entire consolidated scan output.
type CompleteScanReport struct {
	ScanID            string            `json:"scan_id"`
	Target            string            `json:"target"`
	ScanDate          string            `json:"scan_date"`
	DurationSeconds   float64           `json:"duration_seconds"`
	Hosts             []HostScanReport  `json:"hosts"`
	TotalHosts        int               `json:"total_hosts"`
	TotalOpenPorts    int               `json:"total_open_ports"`
	TotalVulns        int               `json:"total_vulns"`
	TotalFindings     int               `json:"total_findings"`
	SeverityBreakdown map[string]int    `json:"severity_breakdown"`
}

// NewHostInfo creates a new HostInfo with current UTC timestamp.
func NewHostInfo(ip, method string) HostInfo {
	return HostInfo{
		IP:              ip,
		DiscoveryMethod: method,
		State:           "alive",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	}
}

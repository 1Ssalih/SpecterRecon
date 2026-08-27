package core

import "time"

// DNSFinding represents a single DNS resolution or subdomain finding.
type DNSFinding struct {
	Hostname   string `json:"hostname"`
	IP         string `json:"ip"`
	RecordType string `json:"record_type"` // A, AAAA, CNAME
	Source     string `json:"source"`      // root_resolution, subdomain_bruteforce
}

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

// VersionEvidence represents an evidence item used for service version determination.
type VersionEvidence struct {
	Source     string `json:"source"`
	Detail     string `json:"detail"`
	Confidence int    `json:"confidence"`
}

// SSLServiceInfo represents TLS/SSL metadata observed during service discovery.
type SSLServiceInfo struct {
	TLSVersion    string   `json:"tls_version,omitempty"`
	CipherSuite   string   `json:"cipher_suite,omitempty"`
	Subject       string   `json:"subject,omitempty"`
	Issuer        string   `json:"issuer,omitempty"`
	DNSNames      []string `json:"dns_names,omitempty"`
	NotBefore     string   `json:"not_before,omitempty"`
	NotAfter      string   `json:"not_after,omitempty"`
	ObservedHints []string `json:"observed_hints,omitempty"`
}

// ProbeResult represents the internal result of active or passive protocol probing.
type ProbeResult struct {
	ServiceName string
	ServiceDesc string
	Version     string
	Banner      string
	ProbeUsed   string
	Confidence  int
	Evidence    []VersionEvidence
	SSLInfo     *SSLServiceInfo
	IsFinal     bool
}

// ServiceDetail represents detailed banner & version information.
type ServiceDetail struct {
	IP                 string            `json:"ip"`
	Port               int               `json:"port"`
	Protocol           string            `json:"protocol"`
	ServiceName        string            `json:"service_name"`
	ServiceDescription string            `json:"service_description,omitempty"`
	ServiceVersion     string            `json:"service_version,omitempty"`
	BannerRaw          string            `json:"banner_raw,omitempty"`
	HTTPTitle          string            `json:"http_title,omitempty"`
	HTTPServer         string            `json:"http_server,omitempty"`
	HTTPTechnologies   []string          `json:"http_technologies"`
	DetectedTechs      []string          `json:"detected_techs,omitempty"`
	VersionSource      string            `json:"version_source,omitempty"`
	VersionConfidence  int               `json:"version_confidence,omitempty"`
	ProbeUsed          string            `json:"probe_used,omitempty"`
	Evidence           []VersionEvidence `json:"evidence,omitempty"`
	SSLEnabled         bool              `json:"ssl_enabled"`
	SSLInfo            *SSLServiceInfo   `json:"ssl_info,omitempty"`
	State              string            `json:"state"`
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
	WordlistMatched  string   `json:"wordlist_matched,omitempty"`
	MatchedTech      string   `json:"matched_tech,omitempty"`
}

// --- Genişletilmiş Pasif Recon Struct'ları ---

// SslFinding represents SSL/TLS audit results for a single endpoint.
type SslFinding struct {
	IP              string   `json:"ip"`
	Port            int      `json:"port"`
	Subject         string   `json:"subject"`
	Issuer          string   `json:"issuer"`
	SANs            []string `json:"sans,omitempty"`
	ExpiryDate      string   `json:"expiry_date"`
	DaysUntilExpiry int      `json:"days_until_expiry"`
	IsExpired       bool     `json:"is_expired"`
	IsSelfSigned    bool     `json:"is_self_signed"`
	WeakProtocols   []string `json:"weak_protocols,omitempty"` // SSLv3, TLSv1.0, TLSv1.1
	WeakCiphers     []string `json:"weak_ciphers,omitempty"`
	Severity        string   `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Notes           []string `json:"notes,omitempty"`
}

// HttpAuditFinding represents HTTP security audit results for a URL.
type HttpAuditFinding struct {
	URL              string            `json:"url"`
	IP               string            `json:"ip"`
	Port             int               `json:"port"`
	MissingHeaders   []string          `json:"missing_headers,omitempty"`   // HSTS, CSP, X-Frame-Options
	DangerousMethods []string          `json:"dangerous_methods,omitempty"` // PUT, DELETE, TRACE
	CORSIssues       []string          `json:"cors_issues,omitempty"`
	OpenRedirect     bool              `json:"open_redirect"`
	GraphQLOpen      bool              `json:"graphql_open"`
	RobotsFound      bool              `json:"robots_found"`
	RobotsPaths      []string          `json:"robots_paths,omitempty"`
	CookieIssues     []string          `json:"cookie_issues,omitempty"`
	ServerHeader     string            `json:"server_header,omitempty"`
	Severity         string            `json:"severity"`
	ExtraInfo        map[string]string `json:"extra_info,omitempty"`
}

// SshAuditFinding represents SSH configuration audit results.
type SshAuditFinding struct {
	IP             string   `json:"ip"`
	Port           int      `json:"port"`
	Banner         string   `json:"banner,omitempty"`
	WeakAlgorithms []string `json:"weak_algorithms,omitempty"` // DSA, RSA<2048, MD5-HMAC
	PasswordAuthOn bool     `json:"password_auth_on"`          // şifre girişi aktif mi?
	RootLoginOn    bool     `json:"root_login_on"`             // root girişi izni var mı?
	Severity       string   `json:"severity"`
	Notes          []string `json:"notes,omitempty"`
}

// HostScanReport aggregates all findings for a single host.
type HostScanReport struct {
	Host        HostInfo         `json:"host"`
	Ports       []PortInfo       `json:"ports"`
	Services    []ServiceDetail  `json:"services"`
	DirFindings []DirFuzzFinding `json:"dir_findings"`
}

// CompleteScanReport represents the entire consolidated scan output.
type CompleteScanReport struct {
	ScanID          string           `json:"scan_id"`
	Target          string           `json:"target"`
	ScanDate        string           `json:"scan_date"`
	ScanProfile     string           `json:"scan_profile,omitempty"` // basic, extended
	DurationSeconds float64          `json:"duration_seconds"`
	DNSFindings     []DNSFinding     `json:"dns_findings,omitempty"`
	TotalDNSRecords int              `json:"total_dns_records"`
	Hosts           []HostScanReport `json:"hosts"`
	TotalHosts      int              `json:"total_hosts"`
	TotalOpenPorts  int              `json:"total_open_ports"`
	TotalFindings   int              `json:"total_findings"`
	// Pasif genişletilmiş modül bulguları
	SslFindings       []SslFinding       `json:"ssl_findings,omitempty"`
	HttpAuditFindings []HttpAuditFinding `json:"http_audit_findings,omitempty"`
	SshAuditFindings  []SshAuditFinding  `json:"ssh_audit_findings,omitempty"`
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

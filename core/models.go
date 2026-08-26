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
	WordlistMatched  string   `json:"wordlist_matched,omitempty"`
}

// --- Yeni Modül Struct'ları ---

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

// SmbFinding represents SMB/NetBIOS enumeration results.
type SmbFinding struct {
	IP             string   `json:"ip"`
	Port           int      `json:"port"`
	NetbiosName    string   `json:"netbios_name,omitempty"`
	Domain         string   `json:"domain,omitempty"`
	OS             string   `json:"os,omitempty"`
	Shares         []string `json:"shares,omitempty"`
	NullSession    bool     `json:"null_session"`    // anonim erişim var mı?
	SigningDisabled bool     `json:"signing_disabled"` // relay saldırısı riski
	SMBv1Enabled   bool     `json:"smbv1_enabled"`   // EternalBlue riski
	Severity       string   `json:"severity"`
	Notes          []string `json:"notes,omitempty"`
}

// FtpFinding represents FTP service audit results.
type FtpFinding struct {
	IP          string   `json:"ip"`
	Port        int      `json:"port"`
	Banner      string   `json:"banner,omitempty"`
	AnonLogin   bool     `json:"anon_login"`   // anonymous erişim var mı?
	AnonWritable bool    `json:"anon_writable"` // dosya yüklenebilir mi?
	FTPSEnabled bool     `json:"ftps_enabled"`
	Severity    string   `json:"severity"`
	Notes       []string `json:"notes,omitempty"`
}

// SmtpFinding represents SMTP service audit results.
type SmtpFinding struct {
	IP          string   `json:"ip"`
	Port        int      `json:"port"`
	Banner      string   `json:"banner,omitempty"`
	OpenRelay   bool     `json:"open_relay"`
	VRFYEnabled bool     `json:"vrfy_enabled"`
	EXPNEnabled bool     `json:"expn_enabled"`
	StarttlsOK  bool     `json:"starttls_ok"`
	Users       []string `json:"users,omitempty"` // VRFY ile bulunan kullanıcılar
	Severity    string   `json:"severity"`
	Notes       []string `json:"notes,omitempty"`
}

// SnmpFinding represents SNMP enumeration results.
type SnmpFinding struct {
	IP          string   `json:"ip"`
	Port        int      `json:"port"`
	Community   string   `json:"community"`   // bulunan community string
	Version     string   `json:"version"`     // v1, v2c, v3
	SysDescr    string   `json:"sys_descr,omitempty"`
	SysName     string   `json:"sys_name,omitempty"`
	SysLocation string   `json:"sys_location,omitempty"`
	SysContact  string   `json:"sys_contact,omitempty"`
	Interfaces  []string `json:"interfaces,omitempty"`
	Severity    string   `json:"severity"`
	Notes       []string `json:"notes,omitempty"`
}

// DbFinding represents database service enumeration results.
type DbFinding struct {
	IP           string   `json:"ip"`
	Port         int      `json:"port"`
	DbType       string   `json:"db_type"` // mysql, mssql, postgresql, mongodb, redis, memcached, elasticsearch
	Version      string   `json:"version,omitempty"`
	AnonAccess   bool     `json:"anon_access"`   // kimlik doğrulamasız erişim
	DefaultCreds bool     `json:"default_creds"` // default şifreyle giriş yapıldı
	Username     string   `json:"username,omitempty"`
	Password     string   `json:"password,omitempty"`
	Databases    []string `json:"databases,omitempty"` // liste edilebilen db'ler
	Severity     string   `json:"severity"`
	Notes        []string `json:"notes,omitempty"`
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

// CredFinding represents a successful default credential attempt.
type CredFinding struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // ssh, ftp, mysql, http, rdp, vnc, redis...
	Username string `json:"username"`
	Password string `json:"password"`
	Severity string `json:"severity"` // her zaman CRITICAL
}

// ContainerFinding represents Docker/Kubernetes/Cloud exposure findings.
type ContainerFinding struct {
	IP        string   `json:"ip"`
	Port      int      `json:"port"`
	Service   string   `json:"service"`             // docker, kubernetes, etcd, consul, prometheus, grafana
	Exposed   bool     `json:"exposed"`             // kimlik doğrulamasız erişim
	Version   string   `json:"version,omitempty"`
	Endpoints []string `json:"endpoints,omitempty"` // açık endpoint'ler
	Severity  string   `json:"severity"`
	Notes     []string `json:"notes,omitempty"`
}

// LdapFinding represents LDAP/Active Directory enumeration results.
type LdapFinding struct {
	IP            string   `json:"ip"`
	Port          int      `json:"port"`
	AnonymousBind bool     `json:"anonymous_bind"`
	DomainName    string   `json:"domain_name,omitempty"`
	NamingContext string   `json:"naming_context,omitempty"`
	ServerType    string   `json:"server_type,omitempty"` // ActiveDirectory, OpenLDAP
	Severity      string   `json:"severity"`
	Notes         []string `json:"notes,omitempty"`
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
	ScanID            string             `json:"scan_id"`
	Target            string             `json:"target"`
	ScanDate          string             `json:"scan_date"`
	ScanProfile       string             `json:"scan_profile,omitempty"` // web, network, ad, database, ssl, full
	DurationSeconds   float64            `json:"duration_seconds"`
	DNSFindings       []DNSFinding       `json:"dns_findings,omitempty"`
	TotalDNSRecords   int                `json:"total_dns_records"`
	Hosts             []HostScanReport   `json:"hosts"`
	TotalHosts        int                `json:"total_hosts"`
	TotalOpenPorts    int                `json:"total_open_ports"`
	TotalVulns        int                `json:"total_vulns"`
	TotalFindings     int                `json:"total_findings"`
	SeverityBreakdown map[string]int     `json:"severity_breakdown"`
	// Yeni modül bulguları
	SslFindings       []SslFinding       `json:"ssl_findings,omitempty"`
	HttpAuditFindings []HttpAuditFinding `json:"http_audit_findings,omitempty"`
	SmbFindings       []SmbFinding       `json:"smb_findings,omitempty"`
	FtpFindings       []FtpFinding       `json:"ftp_findings,omitempty"`
	SmtpFindings      []SmtpFinding      `json:"smtp_findings,omitempty"`
	SnmpFindings      []SnmpFinding      `json:"snmp_findings,omitempty"`
	DbFindings        []DbFinding        `json:"db_findings,omitempty"`
	SshAuditFindings  []SshAuditFinding  `json:"ssh_audit_findings,omitempty"`
	CredFindings      []CredFinding      `json:"cred_findings,omitempty"`
	ContainerFindings []ContainerFinding `json:"container_findings,omitempty"`
	LdapFindings      []LdapFinding      `json:"ldap_findings,omitempty"`
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

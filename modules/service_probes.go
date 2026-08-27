package modules

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

// ProbeMatchRule defines a prioritized, confidence-rated regex rule for service identification.
type ProbeMatchRule struct {
	Pattern     *regexp.Regexp
	ServiceName string
	Description string
	VersionExpr string
	Priority    int // Lower number = higher priority
	Confidence  int // 0 to 100
}

// ProbeSpec defines probing characteristics and rules for specific ports / protocols.
type ProbeSpec struct {
	Name           string
	Ports          []int
	ReadFirst      bool
	InitialProbe   []byte
	FollowupProbes [][]byte
	MaxReads       int
	BinaryParser   func(port int, data []byte) (core.ProbeResult, bool)
	MatchRules     []ProbeMatchRule
}

// CombineConfidence calculates an aggregate confidence score from multiple evidence scores.
func CombineConfidence(values []int) int {
	if len(values) == 0 {
		return 0
	}
	max := 0
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	bonus := (len(values) - 1) * 5
	final := max + bonus
	if final > 100 {
		final = 100
	}
	return final
}

// ProbeRegistry contains protocol specifications for fast, accurate service and version discovery.
var ProbeRegistry = []ProbeSpec{
	// 1. SSH (Port 22, 2222)
	{
		Name:      "ssh",
		Ports:     []int{22, 2222},
		ReadFirst: true,
		FollowupProbes: [][]byte{
			[]byte("SSH-2.0-SpecterRecon_0.8.0\r\n"),
		},
		MaxReads: 2,
		MatchRules: []ProbeMatchRule{
			{
				Pattern:     regexp.MustCompile(`(?i)SSH-[\d.]+-OpenSSH[_\s]([\w.\-p]+)`),
				ServiceName: "ssh",
				Description: "OpenSSH",
				VersionExpr: "$1",
				Priority:    1,
				Confidence:  95,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)SSH-[\d.]+-Dropbear[_\s]([\d.]+)`),
				ServiceName: "ssh",
				Description: "Dropbear SSH",
				VersionExpr: "$1",
				Priority:    1,
				Confidence:  90,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)SSH-[\d.]+-libssh[_\s]([\w.\-]+)`),
				ServiceName: "ssh",
				Description: "libssh",
				VersionExpr: "$1",
				Priority:    2,
				Confidence:  90,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)SSH-[\d.]+-([^\r\n]+)`),
				ServiceName: "ssh",
				Description: "SSH Server",
				VersionExpr: "$1",
				Priority:    10,
				Confidence:  75,
			},
		},
	},

	// 2. FTP (Port 21, 2121)
	{
		Name:      "ftp",
		Ports:     []int{21, 2121},
		ReadFirst: true,
		FollowupProbes: [][]byte{
			[]byte("SYST\r\n"),
			[]byte("HELP\r\n"),
		},
		MaxReads: 3,
		MatchRules: []ProbeMatchRule{
			{
				Pattern:     regexp.MustCompile(`(?i)vsftpd[\s/]?([\d.]+)`),
				ServiceName: "ftp",
				Description: "vsftpd",
				VersionExpr: "$1",
				Priority:    1,
				Confidence:  90,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)ProFTPD[\s/]?([\d.]+)`),
				ServiceName: "ftp",
				Description: "ProFTPD",
				VersionExpr: "$1",
				Priority:    1,
				Confidence:  90,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)Pure-FTPd(?:\s+([\d.]+))?`),
				ServiceName: "ftp",
				Description: "Pure-FTPd",
				VersionExpr: "$1",
				Priority:    2,
				Confidence:  85,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)FileZilla Server(?:\s+version)?\s+([\d.]+)`),
				ServiceName: "ftp",
				Description: "FileZilla Server",
				VersionExpr: "$1",
				Priority:    1,
				Confidence:  90,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)Microsoft FTP Service(?:\s+Version\s+([\d.]+))?`),
				ServiceName: "ftp",
				Description: "Microsoft FTP Service",
				VersionExpr: "$1",
				Priority:    3,
				Confidence:  80,
			},
		},
	},

	// 3. SMTP (Port 25, 465, 587)
	{
		Name:      "smtp",
		Ports:     []int{25, 465, 587},
		ReadFirst: true,
		FollowupProbes: [][]byte{
			[]byte("EHLO recon.local\r\n"),
			[]byte("HELO recon.local\r\n"),
		},
		MaxReads: 3,
		MatchRules: []ProbeMatchRule{
			{
				Pattern:     regexp.MustCompile(`(?i)Postfix`),
				ServiceName: "smtp",
				Description: "Postfix SMTP",
				VersionExpr: "",
				Priority:    2,
				Confidence:  85,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)Exim[\s/]([\d.]+)`),
				ServiceName: "smtp",
				Description: "Exim SMTP",
				VersionExpr: "$1",
				Priority:    1,
				Confidence:  90,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)Sendmail[\s/]([\d.]+)`),
				ServiceName: "smtp",
				Description: "Sendmail",
				VersionExpr: "$1",
				Priority:    2,
				Confidence:  85,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)Microsoft ESMTP MAIL Service(?:\s+Version:\s*([\d.]+))?`),
				ServiceName: "smtp",
				Description: "Microsoft Exchange SMTP",
				VersionExpr: "$1",
				Priority:    2,
				Confidence:  85,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)^220[- ].*SMTP`),
				ServiceName: "smtp",
				Description: "SMTP Server",
				VersionExpr: "",
				Priority:    10,
				Confidence:  70,
			},
		},
	},

	// 4. POP3 (Port 110, 995)
	{
		Name:      "pop3",
		Ports:     []int{110, 995},
		ReadFirst: true,
		FollowupProbes: [][]byte{
			[]byte("CAPA\r\n"),
		},
		MaxReads: 2,
		MatchRules: []ProbeMatchRule{
			{
				Pattern:     regexp.MustCompile(`(?i)Dovecot`),
				ServiceName: "pop3",
				Description: "Dovecot POP3",
				VersionExpr: "",
				Priority:    2,
				Confidence:  85,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)\+OK.*(?:POP3|ready)`),
				ServiceName: "pop3",
				Description: "POP3 Server",
				VersionExpr: "",
				Priority:    10,
				Confidence:  70,
			},
		},
	},

	// 5. IMAP (Port 143, 993)
	{
		Name:      "imap",
		Ports:     []int{143, 993},
		ReadFirst: true,
		FollowupProbes: [][]byte{
			[]byte("a001 CAPABILITY\r\n"),
		},
		MaxReads: 2,
		MatchRules: []ProbeMatchRule{
			{
				Pattern:     regexp.MustCompile(`(?i)Dovecot`),
				ServiceName: "imap",
				Description: "Dovecot IMAP",
				VersionExpr: "",
				Priority:    2,
				Confidence:  85,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)\* OK.*(?:IMAP|ready)`),
				ServiceName: "imap",
				Description: "IMAP Server",
				VersionExpr: "",
				Priority:    10,
				Confidence:  70,
			},
		},
	},

	// 6. Redis (Port 6379)
	{
		Name:         "redis",
		Ports:        []int{6379},
		ReadFirst:    false,
		InitialProbe: []byte("INFO server\r\n"),
		FollowupProbes: [][]byte{
			[]byte("INFO\r\n"),
			[]byte("PING\r\n"),
		},
		MaxReads: 2,
		MatchRules: []ProbeMatchRule{
			{
				Pattern:     regexp.MustCompile(`(?i)redis_version:([\d.]+)`),
				ServiceName: "redis",
				Description: "Redis Key-Value Store",
				VersionExpr: "$1",
				Priority:    1,
				Confidence:  95,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)\+PONG|-NOAUTH|-ERR`),
				ServiceName: "redis",
				Description: "Redis Database",
				VersionExpr: "",
				Priority:    5,
				Confidence:  80,
			},
		},
	},

	// 7. Memcached (Port 11211)
	{
		Name:         "memcached",
		Ports:        []int{11211},
		ReadFirst:    false,
		InitialProbe: []byte("version\r\n"),
		FollowupProbes: [][]byte{
			[]byte("stats\r\n"),
		},
		MaxReads: 2,
		MatchRules: []ProbeMatchRule{
			{
				Pattern:     regexp.MustCompile(`(?i)VERSION\s+([\d.]+)`),
				ServiceName: "memcached",
				Description: "Memcached In-Memory Cache",
				VersionExpr: "$1",
				Priority:    1,
				Confidence:  95,
			},
		},
	},

	// 8. MySQL / MariaDB (Port 3306)
	{
		Name:         "mysql",
		Ports:        []int{3306},
		ReadFirst:    true,
		BinaryParser: ParseMySQLProbe,
		MaxReads:     2,
	},

	// 9. PostgreSQL (Port 5432)
	{
		Name:         "postgresql",
		Ports:        []int{5432},
		ReadFirst:    false,
		InitialProbe: []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}, // SSLRequest packet
		BinaryParser: ParsePostgreSQLProbe,
		MaxReads:     2,
		MatchRules: []ProbeMatchRule{
			{
				Pattern:     regexp.MustCompile(`(?i)PostgreSQL\s+([\d.]+)`),
				ServiceName: "postgresql",
				Description: "PostgreSQL Database Server",
				VersionExpr: "$1",
				Priority:    1,
				Confidence:  90,
			},
		},
	},

	// 10. MongoDB (Port 27017)
	{
		Name:         "mongodb",
		Ports:        []int{27017},
		ReadFirst:    false,
		InitialProbe: []byte{0x3a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'a', 'd', 'm', 'i', 'n', '.', '$', 'c', 'm', 'd', 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x10, 'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
		BinaryParser: ParseMongoDBProbe,
		MaxReads:     2,
	},

	// 11. RDP (Port 3389)
	{
		Name:         "rdp",
		Ports:        []int{3389},
		ReadFirst:    false,
		InitialProbe: []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}, // TPKT / X.224 CR
		BinaryParser: ParseRDPProbe,
		MaxReads:     2,
	},

	// 12. SIP (Port 5060)
	{
		Name:         "sip",
		Ports:        []int{5060},
		ReadFirst:    false,
		InitialProbe: []byte("OPTIONS sip:recon@localhost SIP/2.0\r\nVia: SIP/2.0/TCP localhost\r\nFrom: <sip:recon@localhost>\r\nTo: <sip:target@localhost>\r\nCall-ID: recon\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 1\r\nContent-Length: 0\r\n\r\n"),
		MaxReads:     2,
		MatchRules: []ProbeMatchRule{
			{
				Pattern:     regexp.MustCompile(`(?i)Server:\s*([\w\-./]+)`),
				ServiceName: "sip",
				Description: "SIP VoIP Service",
				VersionExpr: "$1",
				Priority:    1,
				Confidence:  80,
			},
		},
	},
}

// FindProbeSpecByPort locates the most suitable ProbeSpec for a given TCP port.
func FindProbeSpecByPort(port int) ProbeSpec {
	for _, spec := range ProbeRegistry {
		for _, p := range spec.Ports {
			if p == port {
				return spec
			}
		}
	}
	// Fallback generic spec
	return ProbeSpec{
		Name:      "generic",
		ReadFirst: true,
		FollowupProbes: [][]byte{
			[]byte("\r\n\r\n"),
			[]byte("HELP\r\n"),
		},
		MaxReads: 2,
	}
}

// ParseMySQLProbe parses the MySQL initial server greeting / handshake binary packet.
func ParseMySQLProbe(port int, data []byte) (core.ProbeResult, bool) {
	if len(data) < 5 {
		return core.ProbeResult{}, false
	}
	protoVer := data[4]
	if protoVer != 10 && protoVer != 9 {
		return core.ProbeResult{}, false
	}

	nullIdx := -1
	for i := 5; i < len(data); i++ {
		if data[i] == 0 {
			nullIdx = i
			break
		}
	}

	var verStr string
	if nullIdx != -1 {
		verStr = string(data[5:nullIdx])
	} else if len(data) > 5 {
		verStr = string(data[5:])
	}
	verStr = SanitizeBanner(verStr)
	if verStr == "" {
		return core.ProbeResult{}, false
	}

	svcName := "mysql"
	desc := "MySQL Database Server"
	version := verStr

	if strings.Contains(strings.ToLower(verStr), "mariadb") {
		desc = "MariaDB Database Server"
		mariaMatch := regexp.MustCompile(`^([\d.]+)-MariaDB`).FindStringSubmatch(verStr)
		if len(mariaMatch) > 1 {
			version = mariaMatch[1]
		}
	} else {
		mysqlMatch := regexp.MustCompile(`^([\d.]+)`).FindStringSubmatch(verStr)
		if len(mysqlMatch) > 1 {
			version = mysqlMatch[1]
		}
	}

	rawBanner := fmt.Sprintf("MySQL Handshake (Protocol %d, Version %s)", protoVer, verStr)
	return core.ProbeResult{
		ServiceName: svcName,
		ServiceDesc: desc,
		Version:     version,
		Banner:      rawBanner,
		ProbeUsed:   "mysql_handshake_parser",
		Confidence:  95,
		Evidence: []core.VersionEvidence{
			{
				Source:     "binary_parser",
				Detail:     rawBanner,
				Confidence: 95,
			},
		},
		IsFinal: true,
	}, true
}

// ParsePostgreSQLProbe evaluates PostgreSQL SSLRequest responses and error banners.
func ParsePostgreSQLProbe(port int, data []byte) (core.ProbeResult, bool) {
	if len(data) == 0 {
		return core.ProbeResult{}, false
	}
	// PostgreSQL SSLRequest response is a single byte: 'S' (SSL supported) or 'N' (SSL not supported)
	if len(data) == 1 && (data[0] == 'S' || data[0] == 'N') {
		sslDesc := "PostgreSQL (SSL Supported)"
		if data[0] == 'N' {
			sslDesc = "PostgreSQL (SSL Unsupported)"
		}
		return core.ProbeResult{
			ServiceName: "postgresql",
			ServiceDesc: sslDesc,
			Banner:      fmt.Sprintf("PostgreSQL SSLRequest Response: %c", data[0]),
			ProbeUsed:   "postgres_ssl_request",
			Confidence:  75,
			Evidence: []core.VersionEvidence{
				{
					Source:     "postgres_ssl_probe",
					Detail:     fmt.Sprintf("PostgreSQL Response: %c", data[0]),
					Confidence: 75,
				},
			},
			IsFinal: false,
		}, true
	}

	dataStr := string(data)
	if strings.Contains(dataStr, "PostgreSQL") || strings.Contains(dataStr, "FATAL") || strings.Contains(dataStr, "pg_") {
		ver := ""
		re := regexp.MustCompile(`(?i)PostgreSQL\s+([\d.]+)`)
		if m := re.FindStringSubmatch(dataStr); len(m) > 1 {
			ver = m[1]
		}
		return core.ProbeResult{
			ServiceName: "postgresql",
			ServiceDesc: "PostgreSQL Database Server",
			Version:     ver,
			Banner:      SanitizeBanner(dataStr),
			ProbeUsed:   "postgres_probe",
			Confidence:  85,
			Evidence: []core.VersionEvidence{
				{
					Source:     "postgres_error_banner",
					Detail:     SanitizeBanner(dataStr),
					Confidence: 85,
				},
			},
			IsFinal: true,
		}, true
	}

	return core.ProbeResult{}, false
}

// ParseMongoDBProbe parses MongoDB wire protocol responses.
func ParseMongoDBProbe(port int, data []byte) (core.ProbeResult, bool) {
	if len(data) < 16 {
		return core.ProbeResult{}, false
	}
	dataStr := string(data)
	if strings.Contains(dataStr, "ismaster") || strings.Contains(dataStr, "isMaster") || strings.Contains(dataStr, "maxBsonObjectSize") || strings.Contains(dataStr, "version") {
		ver := ""
		re := regexp.MustCompile(`(?i)"version"\s*:\s*"([\d.]+)"`)
		if m := re.FindStringSubmatch(dataStr); len(m) > 1 {
			ver = m[1]
		}
		conf := 80
		if ver != "" {
			conf = 95
		}
		return core.ProbeResult{
			ServiceName: "mongodb",
			ServiceDesc: "MongoDB Database Server",
			Version:     ver,
			Banner:      SanitizeBanner(dataStr),
			ProbeUsed:   "mongodb_wire_probe",
			Confidence:  conf,
			Evidence: []core.VersionEvidence{
				{
					Source:     "mongodb_wire_protocol",
					Detail:     "MongoDB Wire Protocol Response",
					Confidence: conf,
				},
			},
			IsFinal: true,
		}, true
	}
	return core.ProbeResult{}, false
}

// ParseRDPProbe identifies Microsoft Remote Desktop Protocol (RDP) responses.
func ParseRDPProbe(port int, data []byte) (core.ProbeResult, bool) {
	// TPKT packet starts with 0x03 0x00, followed by 2 bytes length, then X.224 CC (0x02 0xf0 0x80)
	if len(data) >= 7 && data[0] == 0x03 && data[1] == 0x00 {
		return core.ProbeResult{
			ServiceName: "rdp",
			ServiceDesc: "Microsoft Terminal Services (RDP)",
			Banner:      "Microsoft RDP (TPKT/X.224 Handshake)",
			ProbeUsed:   "rdp_tpkt_probe",
			Confidence:  85,
			Evidence: []core.VersionEvidence{
				{
					Source:     "rdp_tpkt_handshake",
					Detail:     "TPKT/X.224 Handshake Accepted",
					Confidence: 85,
				},
			},
			IsFinal: true,
		}, true
	}
	return core.ProbeResult{}, false
}

// MatchBannerAgainstRules evaluates text against prioritized match rules and returns the highest-scoring match.
func MatchBannerAgainstRules(spec ProbeSpec, text string) core.ProbeResult {
	if text == "" {
		return core.ProbeResult{}
	}

	type matchCandidate struct {
		rule     ProbeMatchRule
		version  string
		evidence core.VersionEvidence
	}

	var candidates []matchCandidate
	var allRules []ProbeMatchRule
	allRules = append(allRules, spec.MatchRules...)

	// Also append global rules
	for _, specItem := range ProbeRegistry {
		if specItem.Name != spec.Name {
			allRules = append(allRules, specItem.MatchRules...)
		}
	}

	for _, rule := range allRules {
		matches := rule.Pattern.FindStringSubmatch(text)
		if len(matches) > 0 {
			ver := ""
			if rule.VersionExpr == "$1" && len(matches) > 1 {
				ver = SanitizeBanner(matches[1])
			} else if rule.VersionExpr == "$2" && len(matches) > 2 {
				ver = SanitizeBanner(matches[2])
			} else if len(matches) > 1 {
				ver = SanitizeBanner(matches[1])
			}

			candidates = append(candidates, matchCandidate{
				rule:    rule,
				version: ver,
				evidence: core.VersionEvidence{
					Source:     "regex_match",
					Detail:     fmt.Sprintf("%s (%s)", rule.Description, rule.Pattern.String()),
					Confidence: rule.Confidence,
				},
			})
		}
	}

	if len(candidates) == 0 {
		return core.ProbeResult{
			Banner: text,
		}
	}

	// Pick candidate with lowest Priority (highest priority) and highest Confidence
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.rule.Priority < best.rule.Priority {
			best = c
		} else if c.rule.Priority == best.rule.Priority {
			if c.rule.Confidence > best.rule.Confidence {
				best = c
			}
		}
	}

	var evidences []core.VersionEvidence
	var confScores []int
	for _, c := range candidates {
		evidences = append(evidences, c.evidence)
		confScores = append(confScores, c.rule.Confidence)
	}

	return core.ProbeResult{
		ServiceName: best.rule.ServiceName,
		ServiceDesc: best.rule.Description,
		Version:     best.version,
		Banner:      text,
		ProbeUsed:   spec.Name,
		Confidence:  CombineConfidence(confScores),
		Evidence:    evidences,
		IsFinal:     true,
	}
}

// ProbeTLSService performs a safe TLS handshake to collect SSL/TLS certificate metadata and observed hints.
func ProbeTLSService(ip string, port int, timeout time.Duration) *core.SSLServiceInfo {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}

	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ip,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var tlsVerStr string
	switch state.Version {
	case tls.VersionTLS13:
		tlsVerStr = "TLSv1.3"
	case tls.VersionTLS12:
		tlsVerStr = "TLSv1.2"
	case tls.VersionTLS11:
		tlsVerStr = "TLSv1.1"
	case tls.VersionTLS10:
		tlsVerStr = "TLSv1.0"
	case tls.VersionSSL30:
		tlsVerStr = "SSLv3"
	default:
		tlsVerStr = fmt.Sprintf("TLS(0x%04x)", state.Version)
	}

	cipherStr := tls.CipherSuiteName(state.CipherSuite)

	var subject, issuer, notBefore, notAfter string
	var dnsNames []string
	var hints []string

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		subject = cert.Subject.CommonName
		if subject == "" && len(cert.Subject.Organization) > 0 {
			subject = cert.Subject.Organization[0]
		}
		issuer = cert.Issuer.CommonName
		if issuer == "" && len(cert.Issuer.Organization) > 0 {
			issuer = cert.Issuer.Organization[0]
		}
		dnsNames = cert.DNSNames
		notBefore = cert.NotBefore.Format(time.RFC3339)
		notAfter = cert.NotAfter.Format(time.RFC3339)

		combinedCertStr := strings.ToLower(fmt.Sprintf("%s %s %s", subject, issuer, strings.Join(dnsNames, " ")))
		if strings.Contains(combinedCertStr, "let's encrypt") || strings.Contains(combinedCertStr, "letsencrypt") {
			hints = append(hints, "letsencrypt")
		}
		if strings.Contains(combinedCertStr, "iis") || strings.Contains(combinedCertStr, "microsoft") {
			hints = append(hints, "microsoft-iis")
		}
		if strings.Contains(combinedCertStr, "nginx") {
			hints = append(hints, "nginx")
		}
		if strings.Contains(combinedCertStr, "apache") {
			hints = append(hints, "apache")
		}
		if strings.Contains(combinedCertStr, "cpanel") {
			hints = append(hints, "cpanel")
		}
		if strings.Contains(combinedCertStr, "cloudflare") {
			hints = append(hints, "cloudflare")
		}
		if strings.Contains(combinedCertStr, "azure") {
			hints = append(hints, "azure")
		}
		if strings.Contains(combinedCertStr, "localhost") || cert.Issuer.CommonName == cert.Subject.CommonName {
			hints = append(hints, "self-signed")
		}
	}

	return &core.SSLServiceInfo{
		TLSVersion:    tlsVerStr,
		CipherSuite:   cipherStr,
		Subject:       subject,
		Issuer:        issuer,
		DNSNames:      dnsNames,
		NotBefore:     notBefore,
		NotAfter:      notAfter,
		ObservedHints: hints,
	}
}

// GrabServiceBanner connects to a target TCP port, listens passively, probes safely, and extracts high-confidence service info.
func GrabServiceBanner(ip string, port int, timeout time.Duration) core.ProbeResult {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return core.ProbeResult{}
	}
	defer conn.Close()

	spec := FindProbeSpecByPort(port)
	maxReads := spec.MaxReads
	if maxReads <= 0 {
		maxReads = 2
	}

	const maxBannerSize = 65536
	var allData []byte
	buf := make([]byte, 8192)

	// Step 1: Passive reading (for read-first protocols like SSH, FTP, SMTP, MySQL)
	if spec.ReadFirst {
		for i := 0; i < maxReads; i++ {
			_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
			n, rErr := conn.Read(buf)
			if n > 0 {
				allData = append(allData, buf[:n]...)
				if len(allData) >= maxBannerSize {
					allData = allData[:maxBannerSize]
					break
				}
			}
			if rErr != nil || n == 0 {
				break
			}
		}
	}

	// Step 2: If no data was read passively and an initial probe is defined, send it
	if len(allData) == 0 && len(spec.InitialProbe) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(1000 * time.Millisecond))
		_, _ = conn.Write(spec.InitialProbe)

		for i := 0; i < maxReads; i++ {
			_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
			n, rErr := conn.Read(buf)
			if n > 0 {
				allData = append(allData, buf[:n]...)
				if len(allData) >= maxBannerSize {
					allData = allData[:maxBannerSize]
					break
				}
			}
			if rErr != nil || n == 0 {
				break
			}
		}
	}

	// Step 3: If followup probes exist and data is still needed/empty, try followup probes
	if len(allData) == 0 && len(spec.FollowupProbes) > 0 {
		for _, probe := range spec.FollowupProbes {
			_ = conn.SetWriteDeadline(time.Now().Add(1000 * time.Millisecond))
			_, _ = conn.Write(probe)

			for i := 0; i < maxReads; i++ {
				_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
				n, rErr := conn.Read(buf)
				if n > 0 {
					allData = append(allData, buf[:n]...)
					if len(allData) >= maxBannerSize {
						allData = allData[:maxBannerSize]
						break
					}
				}
				if rErr != nil || n == 0 {
					break
				}
			}
			if len(allData) > 0 {
				break
			}
		}
	}

	if len(allData) == 0 {
		return core.ProbeResult{}
	}

	// Step 4: Run Binary Parsers
	if spec.BinaryParser != nil {
		if res, ok := spec.BinaryParser(port, allData); ok {
			return res
		}
	}

	// Check generic binary protocol parser (MySQL, NetBIOS, VNC, etc.)
	sName, sDesc, sVer, binBanner, handled := ParseBinaryProtocolBanner(port, allData)
	if handled && sName != "" {
		return core.ProbeResult{
			ServiceName: sName,
			ServiceDesc: sDesc,
			Version:     sVer,
			Banner:      binBanner,
			ProbeUsed:   "binary_parser",
			Confidence:  90,
			Evidence: []core.VersionEvidence{
				{
					Source:     "binary_parser",
					Detail:     binBanner,
					Confidence: 90,
				},
			},
			IsFinal: true,
		}
	}

	// Step 5: Check unprintable binary junk
	printableCount := 0
	for _, b := range allData {
		if b >= 32 && b <= 126 {
			printableCount++
		}
	}
	if len(allData) > 0 && float64(printableCount)/float64(len(allData)) < 0.35 && !bytes.Contains(allData, []byte("HTTP")) {
		return core.ProbeResult{
			Banner:     "[Binary Protocol Response]",
			ProbeUsed:  "binary_detection",
			Confidence: 50,
		}
	}

	// Step 6: Sanitize text and match against rules
	sanitized := SanitizeBanner(string(allData))
	res := MatchBannerAgainstRules(spec, sanitized)
	return res
}

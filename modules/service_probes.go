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

	// 10. SMB / NetBIOS (Port 445, 139)
	{
		Name:      "microsoft-ds",
		Ports:     []int{445, 139},
		ReadFirst: false,
	},

	// 11. LDAP / LDAPS (Port 389, 636, 3268, 3269)
	{
		Name:      "ldap",
		Ports:     []int{389, 636, 3268, 3269},
		ReadFirst: false,
	},

	// 12. MSRPC Endpoint Mapper (Port 135)
	{
		Name:      "msrpc",
		Ports:     []int{135},
		ReadFirst: false,
		InitialProbe: []byte{
			0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
			0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
			0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11,
			0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xe0, 0x44,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
			0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
			0x02, 0x00, 0x00, 0x00,
		},
		BinaryParser: ParseMSRPCProbe,
		MaxReads:     2,
	},

	// 13. Kerberos (Port 88)
	{
		Name:      "kerberos",
		Ports:     []int{88},
		ReadFirst: false,
		InitialProbe: []byte{
			// ASN.1 AS-REQ (Application 10)
			// Sahte principal ile KRB-ERROR tetikle
			0x6a, 0x81, 0x82, 0x30, 0x81, 0x7f,
			0xa1, 0x03, 0x02, 0x01, 0x05, // pvno: 5
			0xa2, 0x03, 0x02, 0x01, 0x0a, // msg-type: AS-REQ (10)
			0xa4, 0x73, 0x30, 0x71,
			0xa0, 0x07, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10,
			0xa1, 0x14, 0x30, 0x12, 0xa0, 0x03, 0x02, 0x01, 0x01,
			0xa1, 0x0b, 0x30, 0x09, 0x1b, 0x07, 0x72, 0x65, 0x63, 0x6f, 0x6e, 0x00, // cname: "recon"
			0xa2, 0x05, 0x1b, 0x03, 0x41, 0x41, 0x41, // realm: "AAA" (sahte)
			0xa3, 0x1b, 0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x01,
			0xa1, 0x12, 0x04, 0x10,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xa5, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x33, 0x30, 0x31, 0x32, 0x33, 0x31,
			0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
			0xa7, 0x03, 0x02, 0x01, 0x17,
			0xa8, 0x03, 0x02, 0x01, 0x01,
		},
		BinaryParser: ParseKerberosProbe,
		MaxReads:     2,
		MatchRules:   []ProbeMatchRule{},
	},


	// 14. MongoDB (Port 27017)
	{
		Name:         "mongodb",
		Ports:        []int{27017},
		ReadFirst:    false,
		InitialProbe: []byte{0x3a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'a', 'd', 'm', 'i', 'n', '.', '$', 'c', 'm', 'd', 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x10, 'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
		BinaryParser: ParseMongoDBProbe,
		MaxReads:     2,
	},

	// 15. RDP (Port 3389)
	{
		Name:      "rdp",
		Ports:     []int{3389},
		ReadFirst: false,
	},

	// 16. SIP (Port 5060) - Strictly requires SIP/2.0
	{
		Name:         "sip",
		Ports:        []int{5060},
		ReadFirst:    false,
		InitialProbe: []byte("OPTIONS sip:recon@localhost SIP/2.0\r\nVia: SIP/2.0/TCP localhost\r\nFrom: <sip:recon@localhost>\r\nTo: <sip:target@localhost>\r\nCall-ID: recon\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 1\r\nContent-Length: 0\r\n\r\n"),
		MaxReads:     2,
		MatchRules: []ProbeMatchRule{
			{
				Pattern:     regexp.MustCompile(`(?i)(?:SIP/2\.0\s+\d+|OPTIONS\s+sip:).*(?:Server:\s*([\w\-./]+))`),
				ServiceName: "sip",
				Description: "SIP VoIP Service",
				VersionExpr: "$1",
				Priority:    1,
				Confidence:  85,
			},
			{
				Pattern:     regexp.MustCompile(`(?i)^SIP/2\.0`),
				ServiceName: "sip",
				Description: "SIP Service",
				VersionExpr: "",
				Priority:    10,
				Confidence:  75,
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

// ParseMSRPCProbe identifies Microsoft Windows RPC Endpoint Mapper responses (DCERPC Bind Ack).
func ParseMSRPCProbe(port int, data []byte) (core.ProbeResult, bool) {
	if len(data) >= 3 && data[0] == 0x05 && data[1] == 0x00 && data[2] == 0x0c {
		return core.ProbeResult{
			ServiceName: "msrpc",
			ServiceDesc: "Microsoft Windows RPC Endpoint Mapper",
			Banner:      "MSRPC Endpoint Mapper (DCERPC Bind Ack)",
			ProbeUsed:   "msrpc_bind_probe",
			Confidence:  90,
			Evidence: []core.VersionEvidence{
				{
					Source:     "msrpc_dcerpc_bind",
					Detail:     "DCERPC Bind Ack (Version 5.0)",
					Confidence: 90,
				},
			},
			IsFinal: true,
		}, true
	}
	return core.ProbeResult{}, false
}

// ParseKerberosProbe extracts Kerberos Realm names from KRB-ERROR response packets.
func ParseKerberosProbe(port int, data []byte) (core.ProbeResult, bool) {
	if len(data) < 4 {
		return core.ProbeResult{}, false
	}

	// ASN.1 Application tag kontrolü
	appTag := data[0]

	// KRB-ERROR (Application 30 = 0x7e) veya KRB-AS-REP (Application 11 = 0x6b)
	if appTag != 0x7e && appTag != 0x6b {
		return core.ProbeResult{}, false
	}

	dataStr := string(data)
	realm := ""

	// Method 1: Regex ile realm çıkar (en güvenilir)
	// Realm genellikle ASCII uppercase string olarak gelir
	realmRe := regexp.MustCompile(`[A-Z0-9][A-Z0-9\-\.]{3,}(?:\.[A-Z0-9\-]+)+`)
	matches := realmRe.FindAllString(dataStr, -1)
	for _, m := range matches {
		// En uzun match muhtemelen realm'dir
		if len(m) > len(realm) && !strings.Contains(m, ".COM") && !strings.Contains(m, "EXAMPLE") {
			realm = m
		}
	}

	// Method 2: ASN.1 yapıdan manuel parse (fallback)
	if realm == "" {
		// data içinde "DC=" pattern'i ara (LDAP DN formatı)
		dcRe := regexp.MustCompile(`DC=([A-Za-z0-9\-]+)`)
		dcMatches := dcRe.FindAllStringSubmatch(dataStr, -1)
		if len(dcMatches) > 0 {
			var parts []string
			for _, m := range dcMatches {
				parts = append(parts, strings.ToUpper(m[1]))
			}
			realm = strings.Join(parts, ".")
		}
	}

	// Method 3: Binary data içinde printable ASCII string'leri tara
	if realm == "" {
		var candidates []string
		current := ""
		for _, b := range data {
			if (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39) || b == '.' || b == '-' {
				current += string(b)
			} else {
				if len(current) >= 4 && strings.Contains(current, ".") {
					candidates = append(candidates, strings.ToUpper(current))
				}
				current = ""
			}
		}
		if len(current) >= 4 && strings.Contains(current, ".") {
			candidates = append(candidates, strings.ToUpper(current))
		}
		// En uzun candidate'ı realm olarak al
		for _, c := range candidates {
			if len(c) > len(realm) {
				realm = c
			}
		}
	}

	if realm == "" {
		realm = "UNKNOWN_REALM"
	}

	desc := "Kerberos Key Distribution Center"
	banner := "Kerberos Service (KRB-ERROR)"
	if appTag == 0x6b {
		banner = "Kerberos AS-REP Response"
	}
	if realm != "UNKNOWN_REALM" {
		desc = fmt.Sprintf("Kerberos KDC (Realm: %s)", realm)
		banner = fmt.Sprintf("Kerberos KDC (Realm: %s)", realm)
	}

	return core.ProbeResult{
		ServiceName: "kerberos",
		ServiceDesc: desc,
		Version:     realm,
		Banner:      banner,
		ProbeUsed:   "kerberos_asreq_probe",
		Confidence:  90,
		Evidence: []core.VersionEvidence{
			{
				Source:     "kerberos_asreq_error",
				Detail:     banner,
				Confidence: 90,
			},
		},
		IsFinal: true,
	}, true
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

// ProbeRDPService performs an X.224 negotiation request followed by TLS upgrade to extract certificate & hostname.
func ProbeRDPService(ip string, port int, timeout time.Duration) (core.ProbeResult, bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return core.ProbeResult{}, false
	}
	defer conn.Close()

	// TPKT + X.224 Connection Request with RDP Negotiation Request (PROTOCOL_SSL | PROTOCOL_HYBRID)
	rdpNegReq := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT length 19
		0x0e,                   // X.224 length 14
		0xe0,                   // CR
		0x00, 0x00, 0x00, 0x01, 0x00,
		0x01,                   // RDP_NEG_REQ
		0x00,                   // flags
		0x08, 0x00,             // length = 8
		0x03, 0x00, 0x00, 0x00, // PROTOCOL_SSL (0x01) | PROTOCOL_HYBRID (0x02)
	}

	_ = conn.SetWriteDeadline(time.Now().Add(1200 * time.Millisecond))
	if _, err := conn.Write(rdpNegReq); err != nil {
		return core.ProbeResult{}, false
	}

	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	n, err := conn.Read(buf)
	if err != nil || n < 7 {
		return core.ProbeResult{}, false
	}

	if buf[0] == 0x03 && buf[1] == 0x00 {
		var certCN, issuer, tlsVerStr string
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         ip,
			MinVersion:         tls.VersionTLS10,
		})
		_ = tlsConn.SetDeadline(time.Now().Add(2000 * time.Millisecond))
		if hErr := tlsConn.Handshake(); hErr == nil {
			state := tlsConn.ConnectionState()
			switch state.Version {
			case tls.VersionTLS13:
				tlsVerStr = "TLSv1.3"
			case tls.VersionTLS12:
				tlsVerStr = "TLSv1.2"
			case tls.VersionTLS11:
				tlsVerStr = "TLSv1.1"
			case tls.VersionTLS10:
				tlsVerStr = "TLSv1.0"
			}
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				certCN = cert.Subject.CommonName
				issuer = cert.Issuer.CommonName
			}
		}

		banner := "Microsoft Remote Desktop Protocol (RDP)"
		desc := "Microsoft RDP (TLS/NLA)"
		ver := ""
		if certCN != "" {
			banner = fmt.Sprintf("Microsoft RDP (Host: %s, TLS: %s)", certCN, tlsVerStr)
			ver = certCN
		}

		return core.ProbeResult{
			ServiceName: "rdp",
			ServiceDesc: desc,
			Version:     ver,
			Banner:      banner,
			ProbeUsed:   "rdp_tls_negotiate",
			Confidence:  90,
			Evidence: []core.VersionEvidence{
				{
					Source:     "rdp_tls_certificate",
					Detail:     fmt.Sprintf("Subject: %s | Issuer: %s | TLS: %s", certCN, issuer, tlsVerStr),
					Confidence: 90,
				},
			},
			IsFinal: true,
		}, true
	}
	return core.ProbeResult{}, false
}

// ProbeMSSQLService sends a TDS 7.2 Pre-Login packet to extract Microsoft SQL Server exact major/minor/build version.
func ProbeMSSQLService(ip string, port int, timeout time.Duration) (core.ProbeResult, bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return core.ProbeResult{}, false
	}
	defer conn.Close()

	tdsPacket := []byte{
		0x12, 0x01, 0x00, 0x2c, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x1a, 0x00, 0x06,
		0x01, 0x00, 0x20, 0x00, 0x01,
		0x02, 0x00, 0x21, 0x00, 0x01,
		0x03, 0x00, 0x22, 0x00, 0x04,
		0xff,
		0x0f, 0x00, 0x10, 0x5c, 0x00, 0x00,
		0x00,
		0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	_ = conn.SetWriteDeadline(time.Now().Add(1000 * time.Millisecond))
	if _, err := conn.Write(tdsPacket); err != nil {
		return core.ProbeResult{}, false
	}

	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return core.ProbeResult{}, false
	}

	if (buf[0] == 0x04 || buf[0] == 0x12) && n >= 26 {
		for i := 8; i < n-5; i += 5 {
			token := buf[i]
			if token == 0xff {
				break
			}
			if token == 0x00 { // VERSION token
				offset := int(buf[i+1])<<8 | int(buf[i+2])
				length := int(buf[i+3])<<8 | int(buf[i+4])
				targetOffset := offset
				if targetOffset < 8 || targetOffset+length > n {
					if offset+8+length <= n {
						targetOffset = offset + 8
					}
				}
				if targetOffset >= 0 && targetOffset+length <= n && length >= 4 {
					major := int(buf[targetOffset])
					minor := int(buf[targetOffset+1])
					build := int(buf[targetOffset+2])<<8 | int(buf[targetOffset+3])

					editionName := "Microsoft SQL Server"
					switch major {
					case 16:
						editionName = "Microsoft SQL Server 2022"
					case 15:
						editionName = "Microsoft SQL Server 2019"
					case 14:
						editionName = "Microsoft SQL Server 2017"
					case 13:
						editionName = "Microsoft SQL Server 2016"
					case 12:
						editionName = "Microsoft SQL Server 2014"
					case 11:
						editionName = "Microsoft SQL Server 2012"
					case 10:
						if minor == 50 {
							editionName = "Microsoft SQL Server 2008 R2"
						} else {
							editionName = "Microsoft SQL Server 2008"
						}
					case 9:
						editionName = "Microsoft SQL Server 2005"
					}

					verStr := fmt.Sprintf("%d.%d.%d", major, minor, build)
					desc := fmt.Sprintf("%s (%s)", editionName, verStr)
					banner := fmt.Sprintf("TDS Pre-Login Response: %s (v%s)", editionName, verStr)

					return core.ProbeResult{
						ServiceName: "ms-sql-s",
						ServiceDesc: desc,
						Version:     verStr,
						Banner:      banner,
						ProbeUsed:   "tds_prelogin_probe",
						Confidence:  95,
						Evidence: []core.VersionEvidence{
							{
								Source:     "tds_prelogin_handshake",
								Detail:     fmt.Sprintf("Major: %d, Minor: %d, Build: %d (%s)", major, minor, build, editionName),
								Confidence: 95,
							},
						},
						IsFinal: true,
					}, true
				}
			}
		}

		return core.ProbeResult{
			ServiceName: "ms-sql-s",
			ServiceDesc: "Microsoft SQL Server",
			Banner:      "TDS Pre-Login Handshake Accepted",
			ProbeUsed:   "tds_prelogin_probe",
			Confidence:  85,
			Evidence: []core.VersionEvidence{
				{
					Source:     "tds_prelogin",
					Detail:     "TDS 7.x Pre-Login Packet Handshake",
					Confidence: 85,
				},
			},
			IsFinal: true,
		}, true
	}

	return core.ProbeResult{}, false
}

// ProbeWinRMService queries the WS-Management /wsman SOAP endpoint to identify Windows Server version and auth protocols.
func ProbeWinRMService(ip string, port int, timeout time.Duration) (core.ProbeResult, bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return core.ProbeResult{}, false
	}
	defer conn.Close()

	soapBody := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
            xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Header/>
  <s:Body>
    <wsmid:Identify/>
  </s:Body>
</s:Envelope>`

	req := fmt.Sprintf("POST /wsman HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: SpecterRecon/0.9.0\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		ip, port, len(soapBody), soapBody)

	_ = conn.SetWriteDeadline(time.Now().Add(2000 * time.Millisecond))
	if _, err := conn.Write([]byte(req)); err != nil {
		return core.ProbeResult{}, false
	}

	// Timeout'u artır (3000ms → 5000ms)
	buf := make([]byte, 16384)
	_ = conn.SetReadDeadline(time.Now().Add(5000 * time.Millisecond))
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return core.ProbeResult{}, false
	}

	respStr := string(buf[:n])

	// HTTP response header'dan Server bilgisini al
	serverHeader := ""
	if m := regexp.MustCompile(`(?i)Server:\s*([^\r\n]+)`).FindStringSubmatch(respStr); len(m) > 1 {
		serverHeader = strings.TrimSpace(m[1])
	}

	if strings.Contains(respStr, "Microsoft-HTTPAPI") || strings.Contains(respStr, "wsman") || strings.Contains(respStr, "wsmid:") {
		var productVer, vendor, osVersion string

		// ProductVersion parse
		if m := regexp.MustCompile(`(?i)<wsmid:ProductVersion[^>]*>([^<]+)</wsmid:ProductVersion>`).FindStringSubmatch(respStr); len(m) > 1 {
			productVer = strings.TrimSpace(m[1])
		}

		// ProductVendor parse
		if m := regexp.MustCompile(`(?i)<wsmid:ProductVendor[^>]*>([^<]+)</wsmid:ProductVendor>`).FindStringSubmatch(respStr); len(m) > 1 {
			vendor = strings.TrimSpace(m[1])
		}

		// OS: 10.0.17763 pattern'ini geniş regex ile tara
		if m := regexp.MustCompile(`(?i)OS:\s*([\d\.]+)`).FindStringSubmatch(respStr); len(m) > 1 {
			osVersion = strings.TrimSpace(m[1])
		}

		// Alternatif: "Windows Server" pattern'i
		if osVersion == "" {
			if m := regexp.MustCompile(`(?i)(Windows\s+Server\s+[\d\w\s]+)`).FindStringSubmatch(respStr); len(m) > 1 {
				osVersion = strings.TrimSpace(m[1])
			}
		}

		desc := "Microsoft WinRM (WS-Management)"
		if productVer != "" {
			desc = fmt.Sprintf("Microsoft WinRM (%s)", productVer)
		}
		if osVersion != "" {
			desc = fmt.Sprintf("Microsoft WinRM (%s, OS: %s)", productVer, osVersion)
		}

		banner := "Microsoft-HTTPAPI/2.0 (WinRM /wsman)"
		if vendor != "" && productVer != "" {
			banner = fmt.Sprintf("%s %s (WS-Management)", vendor, productVer)
		}
		if osVersion != "" {
			banner += fmt.Sprintf(" [OS: %s]", osVersion)
		}

		// OS versiyonunu çıkarmak için 10.0.XXXXX pattern'ini analiz et
		if osVersion != "" {
			parts := strings.Split(osVersion, ".")
			if len(parts) >= 3 {
				buildNum := parts[2]
				switch {
				case buildNum >= "26100":
					desc = fmt.Sprintf("Microsoft WinRM (Windows Server 2025, Build %s)", buildNum)
				case buildNum >= "20348":
					desc = fmt.Sprintf("Microsoft WinRM (Windows Server 2022, Build %s)", buildNum)
				case buildNum >= "17763":
					desc = fmt.Sprintf("Microsoft WinRM (Windows Server 2019, Build %s)", buildNum)
				case buildNum >= "14393":
					desc = fmt.Sprintf("Microsoft WinRM (Windows Server 2016, Build %s)", buildNum)
				case buildNum >= "9600":
					desc = fmt.Sprintf("Microsoft WinRM (Windows Server 2012 R2, Build %s)", buildNum)
				}
			}
		}

		return core.ProbeResult{
			ServiceName: "http",
			ServiceDesc: desc,
			Version:     productVer,
			Banner:      banner,
			ProbeUsed:   "winrm_wsman_probe",
			Confidence:  90,
			Evidence: []core.VersionEvidence{
				{
					Source:     "wsman_soap_identify",
					Detail:     banner,
					Confidence: 90,
				},
			},
			IsFinal: true,
		}, true
	}

	// SOAP response gelmedi ama Server header Microsoft-HTTPAPI ise WinRM olarak etiketle
	if strings.Contains(serverHeader, "Microsoft-HTTPAPI") {
		return core.ProbeResult{
			ServiceName: "http",
			ServiceDesc: "Microsoft WinRM (WS-Management) - SOAP Identify timeout",
			Version:     serverHeader,
			Banner:      fmt.Sprintf("%s (WinRM detected via Server header, SOAP response timeout)", serverHeader),
			ProbeUsed:   "winrm_header_fallback",
			Confidence:  70,
			Evidence: []core.VersionEvidence{
				{
					Source:     "server_header",
					Detail:     serverHeader,
					Confidence: 70,
				},
			},
			IsFinal: true,
		}, true
	}

	return core.ProbeResult{}, false
}


// ProbeOracleTNSService probes Oracle TNS Listener on port 1521.
func ProbeOracleTNSService(ip string, port int, timeout time.Duration) (core.ProbeResult, bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return core.ProbeResult{}, false
	}
	defer conn.Close()

	connectData := "(DESCRIPTION=(CONNECT_DATA=(COMMAND=version)))"
	pktLen := 58 + len(connectData)
	tnsPacket := []byte{
		byte(pktLen >> 8), byte(pktLen & 0xff),
		0x00, 0x00,
		0x01,
		0x00,
		0x00, 0x00,
		0x01, 0x39,
		0x01, 0x2c,
		0x00, 0x00,
		0x08, 0x00,
		0x7f, 0xff,
		0x7f, 0x08,
		0x00, 0x00,
		0x01, 0x00,
		byte(len(connectData) >> 8), byte(len(connectData) & 0xff),
		0x00, 0x3a,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	tnsPacket = append(tnsPacket, []byte(connectData)...)

	_ = conn.SetWriteDeadline(time.Now().Add(1000 * time.Millisecond))
	if _, err := conn.Write(tnsPacket); err != nil {
		return core.ProbeResult{}, false
	}

	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return core.ProbeResult{}, false
	}

	respStr := string(buf[:n])
	if strings.Contains(respStr, "TNSLSNR") || strings.Contains(respStr, "Oracle") || strings.Contains(respStr, "VSN") {
		ver := ""
		re := regexp.MustCompile(`(?i)Version\s+([\d.]+)`)
		if m := re.FindStringSubmatch(respStr); len(m) > 1 {
			ver = m[1]
		}
		banner := SanitizeBanner(respStr)
		if len(banner) > 100 {
			banner = banner[:97] + "..."
		}

		return core.ProbeResult{
			ServiceName: "oracle-tns",
			ServiceDesc: "Oracle TNS Listener",
			Version:     ver,
			Banner:      banner,
			ProbeUsed:   "oracle_tns_probe",
			Confidence:  90,
			Evidence: []core.VersionEvidence{
				{
					Source:     "oracle_tns_connect",
					Detail:     banner,
					Confidence: 90,
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

	// CRITICAL GUARD: If text is clearly an HTTP response, never match SIP or other protocol rules
	isHTTPText := strings.HasPrefix(text, "HTTP/") || strings.Contains(text, "HTTP/1.") || strings.Contains(text, "HTTP/2.") || strings.Contains(text, "Microsoft-HTTPAPI") || strings.Contains(text, "<html") || strings.Contains(text, "<HTML")

	type matchCandidate struct {
		rule     ProbeMatchRule
		version  string
		evidence core.VersionEvidence
	}

	var candidates []matchCandidate
	var allRules []ProbeMatchRule
	allRules = append(allRules, spec.MatchRules...)

	// Append global rules, but protect against cross-service false positives
	for _, specItem := range ProbeRegistry {
		if specItem.Name != spec.Name {
			for _, r := range specItem.MatchRules {
				if isHTTPText && r.ServiceName == "sip" {
					continue // Skip SIP rules for HTTP text
				}
				allRules = append(allRules, r)
			}
		}
	}

	for _, rule := range allRules {
		if isHTTPText && rule.ServiceName == "sip" {
			continue
		}
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
func ProbeTLSService(ip string, port int, timeout time.Duration, hostname ...string) *core.SSLServiceInfo {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}

	sniHost := ip
	if len(hostname) > 0 && hostname[0] != "" {
		sniHost = hostname[0]
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sniHost,
		MinVersion:         tls.VersionTLS10,
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
	if timeout <= 0 {
		timeout = 3500 * time.Millisecond
	}

	// 1. Specialized protocol probes for ports that require tailored negotiation
	if port == 445 || port == 139 {
		if res, ok := ProbeSMBService(ip, port, timeout); ok && res.Confidence >= 75 {
			return res
		}
		time.Sleep(100 * time.Millisecond)
		if res, ok := ProbeSMBService(ip, port, timeout+500*time.Millisecond); ok && res.Confidence >= 75 {
			return res
		}
	}

	if port == 389 || port == 636 || port == 3268 || port == 3269 {
		isSSL := port == 636 || port == 3269
		if res, ok := ProbeLDAPService(ip, port, isSSL, timeout); ok && res.Confidence >= 75 {
			return res
		}
		time.Sleep(100 * time.Millisecond)
		if res, ok := ProbeLDAPService(ip, port, isSSL, timeout+500*time.Millisecond); ok && res.Confidence >= 75 {
			return res
		}
	}

	if port == 3389 {
		if res, ok := ProbeRDPService(ip, port, timeout); ok && res.Confidence >= 75 {
			return res
		}
		time.Sleep(100 * time.Millisecond)
		if res, ok := ProbeRDPService(ip, port, timeout+500*time.Millisecond); ok && res.Confidence >= 75 {
			return res
		}
	}

	if port == 1433 {
		if res, ok := ProbeMSSQLService(ip, port, timeout); ok && res.Confidence >= 75 {
			return res
		}
		time.Sleep(100 * time.Millisecond)
		if res, ok := ProbeMSSQLService(ip, port, timeout+500*time.Millisecond); ok && res.Confidence >= 75 {
			return res
		}
	}

	if port == 5985 || port == 5986 {
		if res, ok := ProbeWinRMService(ip, port, timeout); ok && res.Confidence >= 75 {
			return res
		}
		time.Sleep(100 * time.Millisecond)
		if res, ok := ProbeWinRMService(ip, port, timeout+500*time.Millisecond); ok && res.Confidence >= 75 {
			return res
		}
	}

	if port == 1521 {
		if res, ok := ProbeOracleTNSService(ip, port, timeout); ok && res.Confidence >= 75 {
			return res
		}
		time.Sleep(100 * time.Millisecond)
		if res, ok := ProbeOracleTNSService(ip, port, timeout+500*time.Millisecond); ok && res.Confidence >= 75 {
			return res
		}
	}

	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		time.Sleep(120 * time.Millisecond)
		conn, err = net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return core.ProbeResult{}
		}
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
			_ = conn.SetReadDeadline(time.Now().Add(1800 * time.Millisecond))
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

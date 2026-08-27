package modules

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

// BuildLDAPRootDSESearchRequest encodes an anonymous LDAP SearchRequest for RootDSE.
func BuildLDAPRootDSESearchRequest() []byte {
	// Attributes to request
	attrs := []string{
		"defaultNamingContext",
		"dnsHostName",
		"domainControllerFunctionality",
		"domainFunctionality",
		"forestFunctionality",
		"serverName",
		"supportedLDAPVersion",
		"namingContexts",
		"subschemaSubentry",
	}

	var attrSeq []byte
	for _, attr := range attrs {
		attrSeq = append(attrSeq, encodeOctetString(attr)...)
	}
	attrSeqWithHeader := encodeSequence(0x30, attrSeq)

	// Filter: (objectClass=*) -> Context-specific tag 0x87 ("present" filter)
	filter := encodeBER(0x87, []byte("objectClass"))

	var body []byte
	body = append(body, encodeOctetString("")...)             // baseObject: ""
	body = append(body, encodeEnumerated(0)...)                // scope: baseObject (0)
	body = append(body, encodeEnumerated(0)...)                // derefAliases: never (0)
	body = append(body, encodeInteger(0)...)                   // sizeLimit: 0
	body = append(body, encodeInteger(10)...)                  // timeLimit: 10
	body = append(body, encodeBoolean(false)...)               // typesOnly: FALSE
	body = append(body, filter...)                             // filter
	body = append(body, attrSeqWithHeader...)                  // attributes

	// SearchRequest Op = 0x63
	searchReq := encodeSequence(0x63, body)

	// MessageID = 1 (Integer 1)
	msgID := encodeInteger(1)

	return encodeSequence(0x30, append(msgID, searchReq...))
}

func encodeBER(tag byte, val []byte) []byte {
	var l []byte
	length := len(val)
	if length < 128 {
		l = []byte{byte(length)}
	} else if length < 256 {
		l = []byte{0x81, byte(length)}
	} else {
		l = []byte{0x82, byte(length >> 8), byte(length & 0xff)}
	}
	return append(append([]byte{tag}, l...), val...)
}

func encodeSequence(tag byte, val []byte) []byte {
	return encodeBER(tag, val)
}

func encodeOctetString(s string) []byte {
	return encodeBER(0x04, []byte(s))
}

func encodeInteger(v int) []byte {
	return encodeBER(0x02, []byte{byte(v)})
}

func encodeEnumerated(v int) []byte {
	return encodeBER(0x0a, []byte{byte(v)})
}

func encodeBoolean(b bool) []byte {
	val := byte(0x00)
	if b {
		val = 0xff
	}
	return encodeBER(0x01, []byte{val})
}

// LDAPRootDSEInfo holds extracted attributes from LDAP RootDSE response.
type LDAPRootDSEInfo struct {
	DefaultNamingContext          string
	DNSHostName                   string
	DomainControllerFunctionality int
	DomainFunctionality           int
	ForestFunctionality           int
	ServerName                    string
	SupportedLDAPVersions         []string
	NamingContexts                []string
}

// ParseLDAPRootDSEResponse inspects LDAP SearchResultEntry ASN.1/BER response for Active Directory attributes.
func ParseLDAPRootDSEResponse(data []byte) (*LDAPRootDSEInfo, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("response too short")
	}

	info := &LDAPRootDSEInfo{
		DomainControllerFunctionality: -1,
		DomainFunctionality:           -1,
		ForestFunctionality:           -1,
	}

	dataStr := string(data)

	// Extract defaultNamingContext (e.g. DC=milsoft,DC=com,DC=tr)
	if idx := strings.Index(dataStr, "defaultNamingContext"); idx != -1 {
		val := extractNextOctetString(data, idx+len("defaultNamingContext"))
		if val != "" {
			info.DefaultNamingContext = val
		}
	}

	// Extract dnsHostName (e.g. 2012dc1.milsoft.com.tr)
	if idx := strings.Index(dataStr, "dnsHostName"); idx != -1 {
		val := extractNextOctetString(data, idx+len("dnsHostName"))
		if val != "" {
			info.DNSHostName = val
		}
	}

	// Extract serverName
	if idx := strings.Index(dataStr, "serverName"); idx != -1 {
		val := extractNextOctetString(data, idx+len("serverName"))
		if val != "" {
			info.ServerName = val
		}
	}

	// Extract domainControllerFunctionality
	if idx := strings.Index(dataStr, "domainControllerFunctionality"); idx != -1 {
		valStr := extractNextOctetString(data, idx+len("domainControllerFunctionality"))
		if val, err := strconv.Atoi(strings.TrimSpace(valStr)); err == nil {
			info.DomainControllerFunctionality = val
		}
	}

	// Extract domainFunctionality
	if idx := strings.Index(dataStr, "domainFunctionality"); idx != -1 {
		valStr := extractNextOctetString(data, idx+len("domainFunctionality"))
		if val, err := strconv.Atoi(strings.TrimSpace(valStr)); err == nil {
			info.DomainFunctionality = val
		}
	}

	if info.DefaultNamingContext == "" && info.DNSHostName == "" && info.DomainControllerFunctionality == -1 {
		return nil, fmt.Errorf("no LDAP RootDSE attributes identified")
	}

	return info, nil
}

func extractNextOctetString(data []byte, startOffset int) string {
	if startOffset >= len(data) {
		return ""
	}
	limit := startOffset + 48
	if limit > len(data) {
		limit = len(data)
	}

	for i := startOffset; i < limit; i++ {
		if data[i] == 0x04 && i+1 < len(data) {
			l := int(data[i+1])
			valStart := i + 2
			if l > 128 && l&0x80 != 0 {
				numBytes := l & 0x7f
				if i+1+numBytes < len(data) {
					l = 0
					for b := 0; b < numBytes; b++ {
						l = (l << 8) | int(data[i+2+b])
					}
					valStart = i + 2 + numBytes
				}
			}
			if valStart+l <= len(data) {
				return string(data[valStart : valStart+l])
			}
		}
	}
	return ""
}

// FunctionalityLevelToWindowsOS maps Active Directory Domain Controller functionality levels to Windows Server versions.
func FunctionalityLevelToWindowsOS(level int) string {
	switch level {
	case 7:
		return "Windows Server 2016 / 2019 / 2022 / 2025"
	case 6:
		return "Windows Server 2012 R2"
	case 5:
		return "Windows Server 2012"
	case 4:
		return "Windows Server 2008 R2"
	case 3:
		return "Windows Server 2008"
	case 2:
		return "Windows Server 2003"
	case 0:
		return "Windows 2000 Server"
	default:
		if level > 7 {
			return fmt.Sprintf("Windows Server 2022+ (Level %d)", level)
		}
		return fmt.Sprintf("Domain Controller Level %d", level)
	}
}

// ProbeLDAPService connects to LDAP/LDAPS port and performs an anonymous RootDSE search for Active Directory metadata.
func ProbeLDAPService(ip string, port int, isSSL bool, timeout time.Duration) (core.ProbeResult, bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	var conn net.Conn
	var err error

	if isSSL || port == 636 || port == 3269 {
		dialer := &net.Dialer{Timeout: timeout}
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         ip,
			MinVersion:         tls.VersionTLS10,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConf)
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}

	if err != nil {
		return core.ProbeResult{}, false
	}
	defer conn.Close()

	req := BuildLDAPRootDSESearchRequest()
	_ = conn.SetWriteDeadline(time.Now().Add(1200 * time.Millisecond))
	if _, err := conn.Write(req); err != nil {
		return core.ProbeResult{}, false
	}

	buf := make([]byte, 8192)
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		return core.ProbeResult{}, false
	}

	rootDSE, err := ParseLDAPRootDSEResponse(buf[:n])
	if err != nil || rootDSE == nil {
		svc := "ldap"
		if isSSL || port == 636 {
			svc = "ldaps"
		}
		return core.ProbeResult{
			ServiceName: svc,
			ServiceDesc: "Lightweight Directory Access Protocol (LDAP)",
			Banner:      "LDAP Service Active",
			ProbeUsed:   "ldap_bind_probe",
			Confidence:  75,
		}, true
	}

	svcName := "ldap"
	if isSSL || port == 636 {
		svcName = "ldaps"
	}

	osDesc := "Active Directory LDAP"
	verStr := ""
	if rootDSE.DomainControllerFunctionality != -1 {
		osDesc = FunctionalityLevelToWindowsOS(rootDSE.DomainControllerFunctionality)
		verStr = fmt.Sprintf("FuncLevel %d (%s)", rootDSE.DomainControllerFunctionality, osDesc)
	}

	var parts []string
	if rootDSE.DNSHostName != "" {
		parts = append(parts, fmt.Sprintf("DC Host: %s", rootDSE.DNSHostName))
	}
	if rootDSE.DefaultNamingContext != "" {
		parts = append(parts, fmt.Sprintf("Domain: %s", rootDSE.DefaultNamingContext))
	}
	if osDesc != "Active Directory LDAP" {
		parts = append(parts, fmt.Sprintf("OS: %s", osDesc))
	}

	bannerStr := "LDAP RootDSE (" + strings.Join(parts, " | ") + ")"
	if len(parts) == 0 {
		bannerStr = "Active Directory LDAP RootDSE"
	}

	return core.ProbeResult{
		ServiceName: svcName,
		ServiceDesc: fmt.Sprintf("Active Directory LDAP (%s)", osDesc),
		Version:     verStr,
		Banner:      bannerStr,
		ProbeUsed:   "ldap_rootdse_probe",
		Confidence:  90,
		Evidence: []core.VersionEvidence{
			{
				Source:     "ldap_rootdse_query",
				Detail:     bannerStr,
				Confidence: 90,
			},
		},
		IsFinal: true,
	}, true
}

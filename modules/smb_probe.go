package modules

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)


// WindowsBuildToOSName maps Windows NT build numbers to friendly operating system names.
func WindowsBuildToOSName(major, minor byte, build uint16) string {
	switch build {
	case 26100:
		return "Windows 11 24H2 / Windows Server 2025"
	case 22631, 22621:
		return "Windows 11 23H2 / 22H2"
	case 22000:
		return "Windows 11 21H2"
	case 20348:
		return "Windows Server 2022"
	case 19045, 19044, 19043, 19042, 19041:
		return "Windows 10 / Windows Server 20H2"
	case 17763:
		return "Windows Server 2019 / Windows 10 1809"
	case 14393:
		return "Windows Server 2016 / Windows 10 1607"
	case 10586, 10240:
		return "Windows 10"
	case 9600:
		return "Windows Server 2012 R2 / Windows 8.1"
	case 9200:
		return "Windows Server 2012 / Windows 8"
	case 7601:
		return "Windows Server 2008 R2 SP1 / Windows 7 SP1"
	case 7600:
		return "Windows Server 2008 R2 / Windows 7"
	case 6002:
		return "Windows Server 2008 SP2 / Windows Vista SP2"
	case 6001:
		return "Windows Server 2008 SP1 / Windows Vista SP1"
	case 6000:
		return "Windows Vista"
	case 3790:
		return "Windows Server 2003"
	case 2600:
		return "Windows XP"
	case 2195:
		return "Windows 2000"
	default:
		if major == 10 && minor == 0 {
			if build > 22000 {
				return fmt.Sprintf("Windows 11 / Server 2022+ (Build %d)", build)
			}
			if build > 10000 {
				return fmt.Sprintf("Windows 10 / Server 2016-2019 (Build %d)", build)
			}
			return fmt.Sprintf("Windows NT 10.0 (Build %d)", build)
		}
		if major == 6 {
			switch minor {
			case 3:
				return fmt.Sprintf("Windows Server 2012 R2 / Windows 8.1 (Build %d)", build)
			case 2:
				return fmt.Sprintf("Windows Server 2012 / Windows 8 (Build %d)", build)
			case 1:
				return fmt.Sprintf("Windows Server 2008 R2 / Windows 7 (Build %d)", build)
			case 0:
				return fmt.Sprintf("Windows Server 2008 / Windows Vista (Build %d)", build)
			}
		}
		return fmt.Sprintf("Windows NT %d.%d (Build %d)", major, minor, build)
	}
}

// NTLMSSPInfo holds extracted metadata from NTLMSSP Challenge (Type 2) response.
type NTLMSSPInfo struct {
	MajorVersion      byte
	MinorVersion      byte
	BuildNumber       uint16
	OSName            string
	NetBIOSServerName string
	NetBIOSDomainName string
	DNSServerName     string
	DNSDomainName     string
	DNSTreeName       string
}

// BuildSMB2NegotiatePacket creates a NetBIOS + SMB2 Negotiate Protocol Request packet.
func BuildSMB2NegotiatePacket() []byte {
	// SMB2 Negotiate Request (Dialects: 0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
	smb2HeaderAndBody := []byte{
		// SMB2 Header
		0xfe, 'S', 'M', 'B', // ProtocolId: 0xfe 'S' 'M' 'B'
		0x40, 0x00, // StructureSize: 64
		0x00, 0x00, // CreditCharge: 0
		0x00, 0x00, 0x00, 0x00, // Status: 0
		0x00, 0x00, // Command: NEGOTIATE (0x0000)
		0x00, 0x00, // CreditsRequested: 0
		0x00, 0x00, 0x00, 0x00, // Flags: 0
		0x00, 0x00, 0x00, 0x00, // NextCommand: 0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageId: 0
		0x00, 0x00, 0x00, 0x00, // Reserved: ProcessId
		0x00, 0x00, 0x00, 0x00, // TreeId: 0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId: 0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature: 16 bytes

		// SMB2 Negotiate Request Body
		0x24, 0x00, // StructureSize: 36
		0x05, 0x00, // DialectCount: 5
		0x01, 0x00, // SecurityMode: Signing enabled
		0x00, 0x00, // Reserved: 0
		0x7f, 0x00, 0x00, 0x00, // Capabilities
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientGuid
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientStartTime
		0x02, 0x02, // Dialect: SMB 2.0.2
		0x10, 0x02, // Dialect: SMB 2.1
		0x00, 0x03, // Dialect: SMB 3.0
		0x02, 0x03, // Dialect: SMB 3.0.2
		0x11, 0x03, // Dialect: SMB 3.1.1
	}

	netbiosHeader := make([]byte, 4)
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(smb2HeaderAndBody)))
	return append(netbiosHeader, smb2HeaderAndBody...)
}

// BuildSMB2SessionSetupNTLMSSP1 creates SMB2 Session Setup Request containing NTLMSSP Type 1 Negotiate token.
func BuildSMB2SessionSetupNTLMSSP1(sessionId uint64) []byte {
	// NTLMSSP Type 1 Negotiate Token
	ntlmsspToken := []byte{
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00, // Signature
		0x01, 0x00, 0x00, 0x00, // MessageType: 1 (Negotiate)
		0x05, 0xb2, 0x08, 0xa2, // NegotiateFlags: Unicode, OEM, RequestTarget, NTLM, AlwaysSign, ExtendedSecurity, 128bit
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // CallingWorkstation Domain
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // CallingWorkstation Name
		0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f, // OS Version: 6.1 (Build 7601), NTLM Revision 15
	}

	// Security Buffer offset: 64 (Header) + 24 (Session Setup Body) = 88
	secBufferOffset := uint16(88)
	secBufferLen := uint16(len(ntlmsspToken))

	smb2HeaderAndBody := []byte{
		// SMB2 Header
		0xfe, 'S', 'M', 'B', // ProtocolId
		0x40, 0x00, // StructureSize: 64
		0x00, 0x00, // CreditCharge: 0
		0x00, 0x00, 0x00, 0x00, // Status: 0
		0x01, 0x00, // Command: SESSION_SETUP (0x0001)
		0x00, 0x00, // CreditsRequested: 0
		0x00, 0x00, 0x00, 0x00, // Flags: 0
		0x00, 0x00, 0x00, 0x00, // NextCommand: 0
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageId: 1
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // TreeId: 0
	}

	// Append SessionId (8 bytes)
	sessIdBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(sessIdBytes, sessionId)
	smb2HeaderAndBody = append(smb2HeaderAndBody, sessIdBytes...)

	// Signature: 16 bytes zeros
	smb2HeaderAndBody = append(smb2HeaderAndBody, make([]byte, 16)...)

	// SMB2 Session Setup Request Body (24 bytes)
	body := []byte{
		0x19, 0x00, // StructureSize: 25
		0x00,       // Flags: 0
		0x01,       // SecurityMode: 1 (Signing enabled)
		0x00, 0x00, 0x00, 0x00, // Capabilities: 0
		0x00, 0x00, 0x00, 0x00, // Channel: 0
	}

	offsetBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(offsetBytes, secBufferOffset)
	body = append(body, offsetBytes...)

	lenBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBytes, secBufferLen)
	body = append(body, lenBytes...)

	// PreviousSessionId: 8 bytes zeros
	body = append(body, make([]byte, 8)...)

	smb2HeaderAndBody = append(smb2HeaderAndBody, body...)
	smb2HeaderAndBody = append(smb2HeaderAndBody, ntlmsspToken...)

	netbiosHeader := make([]byte, 4)
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(smb2HeaderAndBody)))
	return append(netbiosHeader, smb2HeaderAndBody...)
}

// ParseNTLMSSPChallenge extracts OS build, version, and Active Directory / Computer names from NTLMSSP Type 2 challenge bytes.
func ParseNTLMSSPChallenge(data []byte) (*NTLMSSPInfo, error) {
	// Look for NTLMSSP signature: "NTLMSSP\x00"
	sig := []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00}
	idx := bytes.Index(data, sig)
	if idx == -1 {
		return nil, fmt.Errorf("NTLMSSP signature not found")
	}

	ntlmData := data[idx:]
	if len(ntlmData) < 32 {
		return nil, fmt.Errorf("NTLMSSP payload too short")
	}

	msgType := binary.LittleEndian.PutUint32
	_ = msgType
	typeVal := binary.LittleEndian.Uint32(ntlmData[8:12])
	if typeVal != 2 {
		return nil, fmt.Errorf("expected NTLMSSP Type 2, got %d", typeVal)
	}

	info := &NTLMSSPInfo{}

	// Check if OS Version structure is present (offset 48..56 in Type 2 header)
	if len(ntlmData) >= 56 {
		info.MajorVersion = ntlmData[48]
		info.MinorVersion = ntlmData[49]
		info.BuildNumber = binary.LittleEndian.Uint16(ntlmData[50:52])
		info.OSName = WindowsBuildToOSName(info.MajorVersion, info.MinorVersion, info.BuildNumber)
	}

	// TargetInfo (AV_PAIRS) descriptor: Len at 40..42, Offset at 44..48
	if len(ntlmData) >= 48 {
		targetInfoLen := int(binary.LittleEndian.Uint16(ntlmData[40:42]))
		targetInfoOffset := int(binary.LittleEndian.Uint32(ntlmData[44:48]))

		if targetInfoOffset > 0 && targetInfoOffset+targetInfoLen <= len(ntlmData) {
			avData := ntlmData[targetInfoOffset : targetInfoOffset+targetInfoLen]
			offset := 0
			for offset+4 <= len(avData) {
				avId := binary.LittleEndian.Uint16(avData[offset : offset+2])
				avLen := int(binary.LittleEndian.Uint16(avData[offset+2 : offset+4]))
				offset += 4

				if avId == 0 { // MsvAvEOL
					break
				}

				if offset+avLen > len(avData) {
					break
				}

				valBytes := avData[offset : offset+avLen]
				offset += avLen

				// Decode UTF-16LE string
				valStr := decodeUTF16LE(valBytes)

				switch avId {
				case 1: // MsvAvNbComputerName
					info.NetBIOSServerName = valStr
				case 2: // MsvAvNbDomainName
					info.NetBIOSDomainName = valStr
				case 3: // MsvAvDnsComputerName
					info.DNSServerName = valStr
				case 4: // MsvAvDnsDomainName
					info.DNSDomainName = valStr
				case 5: // MsvAvDnsTreeName (Forest)
					info.DNSTreeName = valStr
				}
			}
		}
	}

	return info, nil
}

// decodeUTF16LE converts UTF-16LE byte sequence into standard Go string.
func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i : i+2])
		if u != 0 {
			runes = append(runes, rune(u))
		}
	}
	return string(runes)
}

// ProbeSMBService connects to SMB port (445 or 139), negotiates SMB2, and extracts NTLMSSP OS/Domain fingerprint without authenticating.
func ProbeSMBService(ip string, port int, timeout time.Duration) (core.ProbeResult, bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return core.ProbeResult{}, false
	}
	defer conn.Close()

	// ============================================================
	// AŞAMA 1: SMB2 Negotiate Request
	// ============================================================
	smb2Negotiate := []byte{
		// NetBIOS Session Service Header (4 bytes)
		0x00, 0x00, 0x00, 0x6C, // Length: 108 bytes

		// SMB2 Header (64 bytes)
		0xFE, 'S', 'M', 'B', // Protocol ID: SMB2
		0x40, 0x00, // Structure Size: 64
		0x00, 0x00, // Credit Charge
		0x00, 0x00, // Status
		0x00, 0x00, // Command: Negotiate
		0x01, 0x00, // Credit Request
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Next Command
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved + Tree ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Process ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID

		// SMB2 Negotiate Request Body
		0x24, 0x00, // Structure Size: 36
		0x08, 0x00, // Dialect Count: 8
		0x01, 0x00, // Security Mode: Signing Enabled
		0x00, 0x00, // Reserved
		0x7F, 0x00, 0x00, 0x00, // Capabilities
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // Client GUID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Negotiate Context Offset/Count
		// Dialects: SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1
		0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03,
		0x11, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	_ = conn.SetWriteDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := conn.Write(smb2Negotiate); err != nil {
		return core.ProbeResult{}, false
	}

	// Negotiate Response oku
	negBuf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(2000 * time.Millisecond))
	n, err := conn.Read(negBuf)
	if err != nil || n < 68 {
		return core.ProbeResult{}, false
	}

	// Check if security buffer in Negotiate response contains NTLMSSP Type 2 directly
	if ntlmInfo, err := ParseNTLMSSPChallenge(negBuf[:n]); err == nil && ntlmInfo.BuildNumber > 0 {
		return buildSMBProbeResult(ntlmInfo, port), true
	}

	// ============================================================
	// AŞAMA 2: SMB2 Session Setup Request (Anonymous/Null Session)
	// NTLMSSP Negotiate (Type 1) gönder
	// ============================================================
	smb2SessionSetup := []byte{
		// NetBIOS Header
		0x00, 0x00, 0x00, 0xA3, // Length: 163 bytes

		// SMB2 Header (64 bytes)
		0xFE, 'S', 'M', 'B',
		0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, // Command: Session Setup
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID: 2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

		// SMB2 Session Setup Request
		0x19, 0x00, // Structure Size: 25
		0x00,       // Flags
		0x00,       // Security Mode
		0x00, 0x00, 0x00, 0x00, // Capabilities
		0x00, 0x00, 0x00, 0x00, // Channel
		0x58, 0x00, // Security Buffer Offset: 88
		0x4B, 0x00, // Security Buffer Length: 75
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Previous Session ID

		// NTLMSSP Negotiate (Type 1) - Anonymous
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00, // Signature
		0x01, 0x00, 0x00, 0x00, // Type: Negotiate
		0x05, 0x02, 0x08, 0x00, // Flags: NTLM, Unicode, OEM
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Domain
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Workstation
		0x06, 0x01, 0xB0, 0x06, 0x00, 0x00, 0x00, 0x0F, // Version (Windows 7)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	_ = conn.SetWriteDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := conn.Write(smb2SessionSetup); err != nil {
		return core.ProbeResult{}, false
	}

	// Session Setup Response oku
	ssBuf := make([]byte, 8192)
	_ = conn.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	ssN, err := conn.Read(ssBuf)
	if err == nil && ssN >= 32 {
		info, parseErr := ParseNTLMSSPChallenge(ssBuf[:ssN])
		if parseErr == nil && info != nil && info.BuildNumber > 0 {
			return buildSMBProbeResult(info, port), true
		}
	}

	// ============================================================
	// AŞAMA 3: FALLBACK — LDAP RootDSE ile OS bilgisi al
	// SMB parse edilemediyse, 389/636 portundan LDAP RootDSE sorgula
	// ============================================================
	ldapPorts := []int{389, 636}
	for _, ldapPort := range ldapPorts {
		if ldapRes, ok := probeLDAPForOSInfo(ip, ldapPort, 2000*time.Millisecond); ok {
			return ldapRes, true
		}
	}

	// ============================================================
	// AŞAMA 4: FALLBACK — NetBIOS Name Query (port 137 UDP)
	// ============================================================
	if nbRes, ok := probeNetBIOSName(ip, 137, 1500*time.Millisecond); ok {
		return nbRes, true
	}

	// Son çare: Session Setup response'u "SMB2 Service" olarak raporla
	return core.ProbeResult{
		ServiceName: "microsoft-ds",
		ServiceDesc: "Microsoft SMB2 Service",
		Banner:      "SMB2 Session Setup Accepted (OS detection failed - try LDAP/NetBIOS fallback)",
		ProbeUsed:   "smb2_session_setup",
		Confidence:  50,
		Evidence: []core.VersionEvidence{
			{
				Source:     "smb2_session_setup",
				Detail:     "NTLMSSP Challenge not received, OS version unknown",
				Confidence: 50,
			},
		},
		IsFinal: true,
	}, true
}

// probeLDAPForOSInfo — LDAP RootDSE üzerinden OS bilgisi çeker (fallback)
func probeLDAPForOSInfo(ip string, port int, timeout time.Duration) (core.ProbeResult, bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	var conn net.Conn
	var err error

	if port == 636 {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		})
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return core.ProbeResult{}, false
	}
	defer conn.Close()

	// LDAP Search Request: (objectClass=*) Base scope, all attributes
	searchReq := []byte{
		0x30, 0x38, // SEQUENCE, length 56
		0x02, 0x01, 0x01, // messageID: 1
		0x63, 0x33, // SearchRequest, length 51
		0x04, 0x00, // baseObject: "" (RootDSE)
		0x0a, 0x01, 0x00, // scope: baseObject
		0x0a, 0x01, 0x00, // derefAliases: neverDerefAliases
		0x02, 0x01, 0x00, // sizeLimit: 0
		0x02, 0x01, 0x00, // timeLimit: 0
		0x01, 0x01, 0x00, // typesOnly: FALSE
		0x87, 0x0e, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x2a, // filter: (objectClass=*)
		0x30, 0x00, // attributes: none (all)
	}

	_ = conn.SetWriteDeadline(time.Now().Add(1000 * time.Millisecond))
	if _, err := conn.Write(searchReq); err != nil {
		return core.ProbeResult{}, false
	}

	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(2000 * time.Millisecond))
	n, err := conn.Read(buf)
	if err != nil || n < 20 {
		return core.ProbeResult{}, false
	}

	// domainControllerFunctionality parse et
	funcLevel := -1
	funcLevelRe := regexp.MustCompile(`domainControllerFunctionality.*?(\d)`)
	if m := funcLevelRe.FindSubmatch(buf[:n]); len(m) > 1 {
		if fl, err := strconv.Atoi(string(m[1])); err == nil {
			funcLevel = fl
		}
	}

	// defaultNamingContext parse et (domain bilgisi)
	namingCtx := ""
	namingCtxRe := regexp.MustCompile(`defaultNamingContext.*?DC=([^,]+)`)
	if m := namingCtxRe.FindSubmatch(buf[:n]); len(m) > 1 {
		namingCtx = strings.ToUpper(string(m[1]))
	}

	// dnsHostName parse et
	dnsHost := ""
	dnsHostRe := regexp.MustCompile(`dnsHostName.*?([a-zA-Z0-9\-\.]+)`)
	if m := dnsHostRe.FindSubmatch(buf[:n]); len(m) > 1 {
		dnsHost = string(m[1])
	}

	if funcLevel < 0 {
		return core.ProbeResult{}, false
	}

	osDesc := FunctionalityLevelToWindowsOS(funcLevel)
	verStr := fmt.Sprintf("FuncLevel %d (%s)", funcLevel, osDesc)

	banner := fmt.Sprintf("LDAP RootDSE (DC Host: %s", dnsHost)
	if namingCtx != "" {
		banner += fmt.Sprintf(", Domain: %s", namingCtx)
	}
	banner += fmt.Sprintf(", %s)", osDesc)

	return core.ProbeResult{
		ServiceName: "microsoft-ds",
		ServiceDesc: fmt.Sprintf("Microsoft SMB (via LDAP: %s)", osDesc),
		Version:     verStr,
		Banner:      banner,
		ProbeUsed:   "ldap_rootdse_fallback",
		Confidence:  85,
		Evidence: []core.VersionEvidence{
			{
				Source:     "ldap_rootdse",
				Detail:     banner,
				Confidence: 85,
			},
		},
		IsFinal: true,
	}, true
}

// probeNetBIOSName — NetBIOS Name Query ile bilgisayar adı ve domain bilgisi çeker
func probeNetBIOSName(ip string, port int, timeout time.Duration) (core.ProbeResult, bool) {
	// NetBIOS Name Query (UDP port 137) — Node Status Request
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return core.ProbeResult{}, false
	}
	defer conn.Close()

	// NetBIOS Node Status Request
	nodeStatusReq := []byte{
		0xA2, 0x48, // Transaction ID
		0x00, 0x00, // Flags: Query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20,                                                                   // Name length: 32
		0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // * (wildcard)
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x00,       // Name terminator
		0x00, 0x21, // Type: NBSTAT
		0x00, 0x01, // Class: IN
	}

	_ = conn.SetWriteDeadline(time.Now().Add(1000 * time.Millisecond))
	if _, err := conn.Write(nodeStatusReq); err != nil {
		return core.ProbeResult{}, false
	}

	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return core.ProbeResult{}, false
	}

	// NetBIOS Name Table parse et
	// Offset 56: Number of names
	nameCount := int(buf[56])
	computerName := ""
	domainName := ""

	offset := 57
	for i := 0; i < nameCount && offset+18 <= n; i++ {
		name := strings.TrimSpace(string(buf[offset : offset+15]))
		nameType := buf[offset+15]
		flags := binary.BigEndian.Uint16(buf[offset+16 : offset+18])

		// Group name flag (bit 15) kontrolü
		isGroup := (flags & 0x8000) != 0

		if nameType == 0x00 && !isGroup && computerName == "" {
			computerName = name
		}
		if nameType == 0x00 && isGroup && domainName == "" {
			domainName = name
		}
		offset += 18
	}

	if computerName == "" && domainName == "" {
		return core.ProbeResult{}, false
	}

	banner := "NetBIOS Node Status"
	if computerName != "" {
		banner += fmt.Sprintf(" (Computer: %s", computerName)
		if domainName != "" {
			banner += fmt.Sprintf(", Domain: %s", domainName)
		}
		banner += ")"
	}

	return core.ProbeResult{
		ServiceName: "microsoft-ds",
		ServiceDesc: "Microsoft SMB (NetBIOS Name Query)",
		Banner:      banner,
		ProbeUsed:   "netbios_name_query",
		Confidence:  60,
		Evidence: []core.VersionEvidence{
			{
				Source:     "netbios_nbstat",
				Detail:     banner,
				Confidence: 60,
			},
		},
		IsFinal: true,
	}, true
}


func buildSMBProbeResult(ntlm *NTLMSSPInfo, port int) core.ProbeResult {
	svcName := "microsoft-ds"
	if port == 139 {
		svcName = "netbios-ssn"
	}

	osName := ntlm.OSName
	if osName == "" {
		osName = fmt.Sprintf("Windows NT %d.%d (Build %d)", ntlm.MajorVersion, ntlm.MinorVersion, ntlm.BuildNumber)
	}

	var parts []string
	if osName != "" {
		parts = append(parts, fmt.Sprintf("OS: %s", osName))
	}
	if ntlm.DNSServerName != "" {
		parts = append(parts, fmt.Sprintf("Host: %s", ntlm.DNSServerName))
	} else if ntlm.NetBIOSServerName != "" {
		parts = append(parts, fmt.Sprintf("NetBIOS: %s", ntlm.NetBIOSServerName))
	}
	if ntlm.DNSDomainName != "" {
		parts = append(parts, fmt.Sprintf("Domain: %s", ntlm.DNSDomainName))
	} else if ntlm.NetBIOSDomainName != "" {
		parts = append(parts, fmt.Sprintf("Domain: %s", ntlm.NetBIOSDomainName))
	}
	if ntlm.DNSTreeName != "" && ntlm.DNSTreeName != ntlm.DNSDomainName {
		parts = append(parts, fmt.Sprintf("Forest: %s", ntlm.DNSTreeName))
	}

	bannerStr := "SMB2 NTLMSSP (" + strings.Join(parts, " | ") + ")"
	verStr := fmt.Sprintf("Build %d", ntlm.BuildNumber)
	if ntlm.BuildNumber == 0 {
		verStr = ""
	}

	return core.ProbeResult{
		ServiceName: svcName,
		ServiceDesc: fmt.Sprintf("Windows SMB (%s)", osName),
		Version:     verStr,
		Banner:      bannerStr,
		ProbeUsed:   "smb2_ntlmssp_probe",
		Confidence:  95,
		Evidence: []core.VersionEvidence{
			{
				Source:     "smb_ntlmssp_os_fingerprint",
				Detail:     bannerStr,
				Confidence: 95,
			},
		},
		IsFinal: true,
	}
}

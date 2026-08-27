package modules

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
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
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return core.ProbeResult{}, false
	}
	defer conn.Close()

	// Step 1: Send SMB2 Negotiate
	negPkt := BuildSMB2NegotiatePacket()
	_ = conn.SetWriteDeadline(time.Now().Add(1200 * time.Millisecond))
	if _, err := conn.Write(negPkt); err != nil {
		return core.ProbeResult{}, false
	}

	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	n, err := conn.Read(buf)
	if err != nil || n < 68 {
		return core.ProbeResult{}, false
	}

	// Verify SMB2 Header signature: 0xfe 'S' 'M' 'B'
	if n < 8 || !bytes.Equal(buf[4:8], []byte{0xfe, 'S', 'M', 'B'}) {
		// Could be SMB1 or invalid response
		return core.ProbeResult{
			ServiceName: "microsoft-ds",
			ServiceDesc: "Microsoft SMB Service",
			Banner:      "SMB Service (Negotiate OK)",
			ProbeUsed:   "smb_negotiate",
			Confidence:  75,
		}, true
	}

	// Extract SessionId if any from header (offset 40 in NetBIOS-encapsulated packet -> 4 + 40 = 44)
	var sessionId uint64
	if n >= 52 {
		sessionId = binary.LittleEndian.Uint64(buf[44:52])
	}

	// Check if security buffer in Negotiate response contains NTLMSSP Type 2 directly
	if ntlmInfo, err := ParseNTLMSSPChallenge(buf[:n]); err == nil && ntlmInfo.BuildNumber > 0 {
		return buildSMBProbeResult(ntlmInfo, port), true
	}

	// Step 2: Send Session Setup with NTLMSSP Type 1
	setupPkt := BuildSMB2SessionSetupNTLMSSP1(sessionId)
	_ = conn.SetWriteDeadline(time.Now().Add(1200 * time.Millisecond))
	if _, err := conn.Write(setupPkt); err != nil {
		return core.ProbeResult{}, false
	}

	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	n, err = conn.Read(buf)
	if err != nil || n < 32 {
		return core.ProbeResult{
			ServiceName: "microsoft-ds",
			ServiceDesc: "Microsoft SMB2 Service",
			Banner:      "SMB2 Session Setup Accepted",
			ProbeUsed:   "smb2_session_setup",
			Confidence:  80,
		}, true
	}

	ntlmInfo, err := ParseNTLMSSPChallenge(buf[:n])
	if err == nil && ntlmInfo != nil {
		return buildSMBProbeResult(ntlmInfo, port), true
	}

	return core.ProbeResult{
		ServiceName: "microsoft-ds",
		ServiceDesc: "Microsoft SMB2 Protocol",
		Banner:      "SMB2 Active",
		ProbeUsed:   "smb2_probe",
		Confidence:  80,
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

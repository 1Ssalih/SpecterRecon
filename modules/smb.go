package modules

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

// AuditSMBService inspects SMB / NetBIOS configuration on a target.
func AuditSMBService(ip string, port int, timeout time.Duration) core.SmbFinding {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	finding := core.SmbFinding{
		IP:       ip,
		Port:     port,
		Severity: "INFO",
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return finding
	}
	defer conn.Close()

	// 1. SMB Header Negotiate Protocol Request (SMB1 / SMB2 probe)
	// SMB1 Negotiate Protocol Packet (Raw Packet Header)
	smb1Negotiate := []byte{
		0x00, 0x00, 0x00, 0x85, // NetBIOS session header
		0xff, 0x53, 0x4d, 0x42, // SMB Header magic (\xFE\x53\x4D\x42)
		0x72,                   // Command: Negotiate Protocol
		0x00, 0x00, 0x00, 0x00, // Status
		0x18, 0x53, 0xc8, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x3d,
		0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e,
		0x31, 0x32, 0x00, 0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e,
		0x30, 0x30, 0x32, 0x00,
	}

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(smb1Negotiate)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)

	if err == nil && n > 8 {
		// Response check for SMB1 (Magic: 0xFF 'S' 'M' 'B') or SMB2 (Magic: 0xFE 'S' 'M' 'B')
		if buf[4] == 0xff && buf[5] == 'S' && buf[6] == 'M' && buf[7] == 'B' {
			finding.SMBv1Enabled = true
			finding.Severity = "HIGH"
			finding.Notes = append(finding.Notes, "SMBv1 Protokolü Aktif (EternalBlue / MS17-010 Zafiyet Riski)")
		}

		// Security Mode Flags in SMB Negotiate Response
		// Offset 29 (in SMB1 header) contains Security Mode: 0x08 = Security Signings Enabled, 0x04 = Required
		if n > 30 {
			securityMode := buf[29]
			if securityMode&0x04 == 0 { // Required bit is NOT set
				finding.SigningDisabled = true
				if finding.Severity != "HIGH" {
					finding.Severity = "MEDIUM"
				}
				finding.Notes = append(finding.Notes, "SMB Signing (İmzalama) Devre Dışı / Zorunlu Değil (NTLM Relay Saldırı Riski)")
			}
		}
	}

	// 2. NetBIOS Name Query on Port 137 UDP
	nbName, domain := QueryNetBIOSName(ip, timeout)
	if nbName != "" {
		finding.NetbiosName = nbName
		finding.Domain = domain
		finding.Notes = append(finding.Notes, fmt.Sprintf("NetBIOS Adı: %s, Domain: %s", nbName, domain))
	}

	// 3. Null Session Probe
	// Test if Anonymous (Null) Session can connect to IPC$
	nullSessConn, errNull := net.DialTimeout("tcp", addr, timeout)
	if errNull == nil {
		defer nullSessConn.Close()
		// Test Null Session SMB2 Session Setup
		smb2NullSetup := []byte{
			0x00, 0x00, 0x00, 0x68,
			0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
		_ = nullSessConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = nullSessConn.Write(smb2NullSetup)

		_ = nullSessConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		nResp, errRead := nullSessConn.Read(buf)
		if errRead == nil && nResp > 8 {
			if buf[4] == 0xfe && buf[5] == 'S' && buf[6] == 'M' && buf[7] == 'B' {
				// Check Status Code (Offset 8-11): STATUS_SUCCESS (0x00000000) or STATUS_MORE_PROCESSING_REQUIRED (0xC0000016)
				statusCode := uint32(buf[8]) | uint32(buf[9])<<8 | uint32(buf[10])<<16 | uint32(buf[11])<<24
				if statusCode == 0x00000000 || statusCode == 0xC0000016 {
					finding.NullSession = true
					finding.Shares = append(finding.Shares, "IPC$ (Null Session Access)")
					if finding.Severity != "CRITICAL" {
						finding.Severity = "HIGH"
					}
					finding.Notes = append(finding.Notes, "SMB Null Session (Anonim Bağlantı) Kabul Ediliyor!")
				}
			}
		}
	}

	return finding
}

// QueryNetBIOSName performs UDP NetBIOS Node Status Request on port 137.
func QueryNetBIOSName(ip string, timeout time.Duration) (name, domain string) {
	addr := net.JoinHostPort(ip, "137")
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return "", ""
	}
	defer conn.Close()

	// NetBIOS Node Status Request Packet
	pkt := []byte{
		0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
		0x00, 0x01,
	}

	_ = conn.SetWriteDeadline(time.Now().Add(1500 * time.Millisecond))
	_, _ = conn.Write(pkt)

	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return "", ""
	}

	// Parse NetBIOS names from response
	numNames := int(buf[56])
	offset := 57
	for i := 0; i < numNames && offset+18 <= n; i++ {
		rawName := strings.TrimSpace(string(buf[offset : offset+15]))
		nameType := buf[offset+15]
		if nameType == 0x00 && name == "" {
			name = rawName
		} else if nameType == 0x00 && domain == "" && rawName != name {
			domain = rawName
		} else if nameType == 0x20 && name == "" {
			name = rawName
		}
		offset += 18
	}

	return name, domain
}

// AuditSMBMultiple scans all SMB services across target hosts.
func AuditSMBMultiple(services []core.ServiceDetail, timeout time.Duration, outputFile string) ([]core.SmbFinding, error) {
	var targets []core.ServiceDetail
	for _, s := range services {
		if s.ServiceName == "microsoft-ds" || s.ServiceName == "netbios-ssn" || s.Port == 445 || s.Port == 139 {
			targets = append(targets, s)
		}
	}

	if len(targets) == 0 {
		return nil, nil
	}

	core.LogInfo("SMB / NetBIOS Güvenlik Denetimi (Null Session, SMBv1, SMB Signing) başlatılıyor (%d SMB servisi)...", len(targets))
	var findings []core.SmbFinding

	for _, t := range targets {
		f := AuditSMBService(t.IP, t.Port, timeout)
		findings = append(findings, f)

		if f.SMBv1Enabled || f.NullSession || f.SigningDisabled {
			core.LogWarning("🚨 SMB Güvenlik Uyarısı (%s:%d): %s", f.IP, f.Port, strings.Join(f.Notes, " | "))
		} else {
			core.LogInfo("SMB Denetim (%s:%d): Güvenli yapılandırma.", f.IP, f.Port)
		}
	}

	if outputFile != "" {
		_ = core.SaveSmbFindings(findings, outputFile)
	}

	return findings, nil
}

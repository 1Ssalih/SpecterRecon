package modules

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

// AuditSNMPService tests UDP 161 with common SNMP community strings.
func AuditSNMPService(ip string, port int, communities []string, timeout time.Duration) core.SnmpFinding {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if len(communities) == 0 {
		communities = []string{"public", "private", "community", "cisco", "manager", "monitor", "read", "write"}
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	finding := core.SnmpFinding{
		IP:       ip,
		Port:     port,
		Version:  "v1/v2c",
		Severity: "INFO",
	}

	for _, comm := range communities {
		// Build SNMPv1 GetRequest for OID .1.3.6.1.2.1.1.1.0 (sysDescr)
		pkt := buildSNMPGetRequest(comm, "1.3.6.1.2.1.1.1.0")

		conn, err := net.DialTimeout("udp", addr, timeout)
		if err != nil {
			continue
		}

		_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		_, _ = conn.Write(pkt)

		_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		buf := make([]byte, 1024)
		n, errRead := conn.Read(buf)
		conn.Close()

		if errRead == nil && n > 20 {
			// SNMP response received! Community string valid!
			finding.Community = comm
			finding.Severity = "HIGH"
			if comm == "private" || comm == "write" {
				finding.Severity = "CRITICAL"
			}

			// Extract printable strings from payload
			rawStr := string(buf[:n])
			cleanStr := extractPrintableString(rawStr)
			if cleanStr != "" {
				finding.SysDescr = cleanStr
			}

			// Also query sysName (.1.3.6.1.2.1.1.5.0)
			pktName := buildSNMPGetRequest(comm, "1.3.6.1.2.1.1.5.0")
			connName, errName := net.DialTimeout("udp", addr, timeout)
			if errName == nil {
				_ = connName.SetWriteDeadline(time.Now().Add(1 * time.Second))
				_, _ = connName.Write(pktName)
				_ = connName.SetReadDeadline(time.Now().Add(1 * time.Second))
				n2, errRead2 := connName.Read(buf)
				connName.Close()
				if errRead2 == nil && n2 > 20 {
					finding.SysName = extractPrintableString(string(buf[:n2]))
				}
			}

			finding.Notes = append(finding.Notes, fmt.Sprintf("GÜVENSİZ SNMP COMMUNITY STRING BULUNDU: '%s'", comm))
			break // Found valid community string
		}
	}

	return finding
}

func buildSNMPGetRequest(community string, oidStr string) []byte {
	commBytes := []byte(community)
	commLen := byte(len(commBytes))

	// Hardcoded SNMPv1 GetRequest Packet template for sysDescr (.1.3.6.1.2.1.1.1.0)
	// Sequence (0x30) -> Version (0x02 0x01 0x00) -> Community -> PDU (GetRequest 0xa0)
	pdu := []byte{
		0xa0, 0x19, // GetRequest PDU, length 25
		0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // Request ID: 1
		0x02, 0x01, 0x00, // Error Status: 0
		0x02, 0x01, 0x00, // Error Index: 0
		0x30, 0x0b, // Varbind List
		0x30, 0x09, // Varbind
		0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID: 1.3.6.1.2.1
		0x05, 0x00, // Null Value
	}

	if oidStr == "1.3.6.1.2.1.1.5.0" {
		// sysName OID: .1.3.6.1.2.1.1.5.0
		pdu = []byte{
			0xa0, 0x1c,
			0x02, 0x04, 0x00, 0x00, 0x00, 0x02,
			0x02, 0x01, 0x00,
			0x02, 0x01, 0x00,
			0x30, 0x0e,
			0x30, 0x0c,
			0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00,
			0x05, 0x00,
		}
	}

	totalPayloadLen := byte(3 + 2 + int(commLen) + len(pdu))
	var pkt []byte
	pkt = append(pkt, 0x30, totalPayloadLen)             // Sequence header
	pkt = append(pkt, 0x02, 0x01, 0x00)                 // Version 1 (0)
	pkt = append(pkt, 0x04, commLen)                    // Octet String Header for Community
	pkt = append(pkt, commBytes...)                     // Community String
	pkt = append(pkt, pdu...)                           // PDU

	return pkt
}

func extractPrintableString(raw string) string {
	var printable []rune
	for _, r := range raw {
		if r >= 32 && r <= 126 {
			printable = append(printable, r)
		} else if len(printable) > 5 {
			break
		}
	}
	res := strings.TrimSpace(string(printable))
	if len(res) > 80 {
		res = res[:77] + "..."
	}
	return res
}

// AuditSNMPMultiple scans UDP 161 across target hosts.
func AuditSNMPMultiple(hosts []core.HostInfo, timeout time.Duration, outputFile string) ([]core.SnmpFinding, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	core.LogInfo("SNMP Community String Brute-Force başlatılıyor (%d host)...", len(hosts))
	var findings []core.SnmpFinding

	for _, h := range hosts {
		f := AuditSNMPService(h.IP, 161, nil, timeout)
		if f.Community != "" {
			findings = append(findings, f)
			core.LogWarning("🚨 CRITICAL SNMP BULGUSU (%s:161): Community String = '%s' | %s", f.IP, f.Community, f.SysDescr)
		}
	}

	if outputFile != "" {
		_ = core.SaveSnmpFindings(findings, outputFile)
	}

	return findings, nil
}

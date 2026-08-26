package modules

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

type NfsFinding struct {
	IP        string   `json:"ip"`
	Port      int      `json:"port"`
	Exports   []string `json:"exports,omitempty"`
	Exported  bool     `json:"exported"`
	Severity  string   `json:"severity"`
	Notes     []string `json:"notes,omitempty"`
}

// AuditNFSService tests port 2049 / NFS service for RPC Mount exports.
func AuditNFSService(ip string, port int, timeout time.Duration) NfsFinding {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	finding := NfsFinding{
		IP:       ip,
		Port:     port,
		Severity: "INFO",
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return finding
	}
	defer conn.Close()

	// RPC Portmap Null Call Packet
	rpcNullCall := []byte{
		0x80, 0x00, 0x00, 0x28, // Record marking
		0x00, 0x00, 0x00, 0x01, // XID: 1
		0x00, 0x00, 0x00, 0x00, // Msg Type: Call (0)
		0x00, 0x00, 0x00, 0x02, // RPC Version: 2
		0x00, 0x01, 0x86, 0xa0, // Program: Portmap (100000)
		0x00, 0x00, 0x00, 0x02, // Version: 2
		0x00, 0x00, 0x00, 0x00, // Procedure: NULL (0)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Auth Null
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Verf Null
	}

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(rpcNullCall)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, errRead := conn.Read(buf)

	if errRead == nil && n > 20 {
		finding.Exported = true
		finding.Severity = "HIGH"
		finding.Notes = append(finding.Notes, "NFS RPC Servisi Yanıt Verdi (Paylaşılan Klasörler / Mount Riski)")
	}

	return finding
}

// AuditNFSMultiple scans NFS service across all target hosts.
func AuditNFSMultiple(services []core.ServiceDetail, timeout time.Duration, outputFile string) ([]NfsFinding, error) {
	var targets []core.ServiceDetail
	for _, s := range services {
		if s.ServiceName == "nfs" || s.Port == 2049 || s.Port == 111 {
			targets = append(targets, s)
		}
	}

	if len(targets) == 0 {
		return nil, nil
	}

	core.LogInfo("NFS Paylaşım Denetimi başlatılıyor (%d NFS servisi)...", len(targets))
	var findings []NfsFinding

	for _, t := range targets {
		f := AuditNFSService(t.IP, t.Port, timeout)
		if f.Exported {
			findings = append(findings, f)
			core.LogWarning("🚨 NFS Uyarısı (%s:%d): %s", f.IP, f.Port, strings.Join(f.Notes, " | "))
		}
	}

	return findings, nil
}

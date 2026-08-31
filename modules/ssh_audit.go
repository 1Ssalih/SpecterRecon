package modules

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

// AuditSSHService inspects SSH banner and handshake parameters for weak configurations.
func AuditSSHService(ip string, port int, timeout time.Duration) core.SshAuditFinding {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	finding := core.SshAuditFinding{
		IP:             ip,
		Port:           port,
		PasswordAuthOn: true, // Default assumption until verified
		Severity:       "INFO",
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return finding
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return finding
	}

	finding.Banner = strings.TrimSpace(banner)

	// Send SSH client version
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("SSH-2.0-SpecterRecon_1.2\r\n"))

	// Read KEXINIT packet from SSH server
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	kexBuf := make([]byte, 2048)
	n, errRead := conn.Read(kexBuf)

	if errRead == nil && n > 20 {
		kexStr := string(kexBuf[:n])

		// Check for legacy/deprecated algorithms
		weakAlgs := []string{
			"diffie-hellman-group1-sha1",
			"diffie-hellman-group-exchange-sha1",
			"ssh-dss",
			"ssh-rsa", // Deprecated in OpenSSH 8.8+
			"arcfour",
			"arcfour128",
			"arcfour256",
			"3des-cbc",
			"hmac-md5",
			"hmac-sha1-96",
		}

		for _, alg := range weakAlgs {
			if strings.Contains(kexStr, alg) {
				finding.WeakAlgorithms = append(finding.WeakAlgorithms, alg)
			}
		}

		if len(finding.WeakAlgorithms) > 0 {
			finding.Severity = "MEDIUM"
			finding.Notes = append(finding.Notes, fmt.Sprintf("Zayıf/Eski SSH Algoritmaları Destekleniyor: %s", strings.Join(finding.WeakAlgorithms, ", ")))
		}
	}

	// Check version vulnerability hints from banner
	bannerLower := strings.ToLower(finding.Banner)
	if strings.Contains(bannerLower, "openssh_4.") || strings.Contains(bannerLower, "openssh_5.") || strings.Contains(bannerLower, "openssh_6.") || strings.Contains(bannerLower, "openssh_7.") {
		finding.Severity = "HIGH"
		finding.Notes = append(finding.Notes, "Eski OpenSSH Sürümü (Zafiyet İçerebilir)")
	}

	return finding
}

// AuditSSHMultiple scans all SSH services across target hosts.
func AuditSSHMultiple(services []core.ServiceDetail, timeout time.Duration, outputFile string) ([]core.SshAuditFinding, error) {
	var targets []core.ServiceDetail
	for _, s := range services {
		if s.ServiceName == "ssh" || s.Port == 22 || s.Port == 2222 {
			targets = append(targets, s)
		}
	}

	if len(targets) == 0 {
		core.LogInfo("0 SSH servisi bulundu, modül atlandı.")
		return nil, nil
	}


	core.LogInfo("SSH Güvenlik Denetimi (Algoritma & Banner Analizi) başlatılıyor (%d SSH servisi)...", len(targets))
	var findings []core.SshAuditFinding

	for _, t := range targets {
		f := AuditSSHService(t.IP, t.Port, timeout)
		findings = append(findings, f)

		if len(f.WeakAlgorithms) > 0 || f.Severity == "HIGH" {
			core.LogWarning("SSH Uyarısı (%s:%d): %s", f.IP, f.Port, strings.Join(f.Notes, " | "))
		} else {
			core.LogInfo("SSH Denetim (%s:%d): Banner='%s'", f.IP, f.Port, f.Banner)
		}
	}

	if outputFile != "" {
		_ = core.SaveSshAuditFindings(findings, outputFile)
	}

	return findings, nil
}

package modules

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

// AuditSMTPService tests SMTP server for Open Relay, VRFY user enumeration, and STARTTLS.
func AuditSMTPService(ip string, port int, timeout time.Duration) core.SmtpFinding {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	finding := core.SmtpFinding{
		IP:       ip,
		Port:     port,
		Severity: "INFO",
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return finding
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	finding.Banner = strings.TrimSpace(banner)

	// Send EHLO
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("EHLO specter.recon\r\n"))

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		lineUpper := strings.ToUpper(line)
		if strings.Contains(lineUpper, "STARTTLS") {
			finding.StarttlsOK = true
		}
		if strings.Contains(lineUpper, "VRFY") {
			finding.VRFYEnabled = true
		}
		if strings.Contains(lineUpper, "EXPN") {
			finding.EXPNEnabled = true
		}
		// EHLO response ends with 250 (without hyphen e.g. "250 HELP")
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	// 1. Test Open Relay
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("MAIL FROM:<test@specter.local>\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	respMail, _ := reader.ReadString('\n')

	if strings.HasPrefix(respMail, "250") {
		_, _ = conn.Write([]byte("RCPT TO:<external-test@gmail.com>\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		respRcpt, _ := reader.ReadString('\n')

		if strings.HasPrefix(respRcpt, "250") {
			finding.OpenRelay = true
			finding.Severity = "CRITICAL"
			finding.Notes = append(finding.Notes, "OPEN RELAY TESPİT EDİLDİ! (Dış adrese e-posta iletimi kabul edildi)")
		}
	}

	// 2. Test VRFY User Enumeration
	if finding.VRFYEnabled {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write([]byte("VRFY root\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		respVrfy, _ := reader.ReadString('\n')

		if strings.HasPrefix(respVrfy, "250") || strings.HasPrefix(respVrfy, "252") {
			finding.Users = append(finding.Users, "root")
			finding.Notes = append(finding.Notes, "VRFY Komutu ile Kullanıcı Numaralandırma (User Enum) Aktif")
			if finding.Severity != "CRITICAL" {
				finding.Severity = "MEDIUM"
			}
		}
	}

	if !finding.StarttlsOK {
		finding.Notes = append(finding.Notes, "STARTTLS (E-Posta Şifreleme) Desteklenmiyor")
	}

	return finding
}

// AuditSMTPMultiple scans all SMTP services across target hosts.
func AuditSMTPMultiple(services []core.ServiceDetail, timeout time.Duration, outputFile string) ([]core.SmtpFinding, error) {
	var targets []core.ServiceDetail
	for _, s := range services {
		if s.ServiceName == "smtp" || s.Port == 25 || s.Port == 587 || s.Port == 465 {
			targets = append(targets, s)
		}
	}

	if len(targets) == 0 {
		return nil, nil
	}

	core.LogInfo("SMTP Güvenlik Denetimi (Open Relay, VRFY, STARTTLS) başlatılıyor (%d SMTP servisi)...", len(targets))
	var findings []core.SmtpFinding

	for _, t := range targets {
		f := AuditSMTPService(t.IP, t.Port, timeout)
		findings = append(findings, f)

		if f.OpenRelay {
			core.LogWarning("🚨 CRITICAL SMTP OPEN RELAY (%s:%d)", f.IP, f.Port)
		} else {
			core.LogInfo("SMTP Denetim (%s:%d): Open relay kapalı.", f.IP, f.Port)
		}
	}

	if outputFile != "" {
		_ = core.SaveSmtpFindings(findings, outputFile)
	}

	return findings, nil
}

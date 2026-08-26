package modules

import (
	"bufio"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

// AuditFTPService checks FTP server for anonymous login, write permissions, and TLS support.
func AuditFTPService(ip string, port int, timeout time.Duration) core.FtpFinding {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	finding := core.FtpFinding{
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

	// 1. Test Anonymous Login
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("USER anonymous\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	respUser, _ := reader.ReadString('\n')

	if strings.HasPrefix(respUser, "331") { // Password required
		_, _ = conn.Write([]byte("PASS anonymous@specter.recon\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		respPass, _ := reader.ReadString('\n')

		if strings.HasPrefix(respPass, "230") { // User logged in
			finding.AnonLogin = true
			finding.Severity = "HIGH"
			finding.Notes = append(finding.Notes, "ANONYMOUS FTP Girişi Başarılı! (USER anonymous / PASS anonymous@)")

			// 2. Test Anonymous Write Access
			_, _ = conn.Write([]byte("MKD specter_test_dir\r\n"))
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			respMkd, _ := reader.ReadString('\n')

			if strings.HasPrefix(respMkd, "257") {
				finding.AnonWritable = true
				finding.Severity = "CRITICAL"
				finding.Notes = append(finding.Notes, "ANONYMOUS Dizin Oluşturma/Yazma Yetkisi Var! (MKD 257)")
				// Clean up test dir
				_, _ = conn.Write([]byte("RMD specter_test_dir\r\n"))
			}
		}
	}

	// 3. Test FTPS (Explicit TLS via AUTH TLS)
	connTLS, errTLS := net.DialTimeout("tcp", addr, timeout)
	if errTLS == nil {
		defer connTLS.Close()
		_ = connTLS.SetReadDeadline(time.Now().Add(2 * time.Second))
		readerTLS := bufio.NewReader(connTLS)
		_, _ = readerTLS.ReadString('\n')

		_, _ = connTLS.Write([]byte("AUTH TLS\r\n"))
		_ = connTLS.SetReadDeadline(time.Now().Add(2 * time.Second))
		respAuth, _ := readerTLS.ReadString('\n')

		if strings.HasPrefix(respAuth, "234") {
			finding.FTPSEnabled = true
			// Upgrade to TLS connection
			tlsConn := tls.Client(connTLS, &tls.Config{InsecureSkipVerify: true})
			if err := tlsConn.Handshake(); err == nil {
				finding.Notes = append(finding.Notes, "FTPS (Explicit TLS) Destekleniyor")
			}
		}
	}

	if !finding.FTPSEnabled && finding.AnonLogin {
		finding.Notes = append(finding.Notes, "Şifresiz Düz Metin (Plaintext) FTP ve TLS Yok")
	}

	return finding
}

// AuditFTPMultiple scans all FTP services found across target hosts.
func AuditFTPMultiple(services []core.ServiceDetail, timeout time.Duration, outputFile string) ([]core.FtpFinding, error) {
	var targets []core.ServiceDetail
	for _, s := range services {
		if s.ServiceName == "ftp" || s.Port == 21 || s.Port == 990 {
			targets = append(targets, s)
		}
	}

	if len(targets) == 0 {
		return nil, nil
	}

	core.LogInfo("FTP Güvenlik Denetimi (Anonymous Login & Write Check) başlatılıyor (%d FTP servisi)...", len(targets))
	var findings []core.FtpFinding

	for _, t := range targets {
		f := AuditFTPService(t.IP, t.Port, timeout)
		findings = append(findings, f)

		if f.AnonLogin {
			core.LogWarning("🚨 CRITICAL FTP Uyarısı (%s:%d): %s", f.IP, f.Port, strings.Join(f.Notes, " | "))
		} else {
			core.LogInfo("FTP Denetim (%s:%d): Anonymous login kapalı.", f.IP, f.Port)
		}
	}

	if outputFile != "" {
		_ = core.SaveFtpFindings(findings, outputFile)
	}

	return findings, nil
}

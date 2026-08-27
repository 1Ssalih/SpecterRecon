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

// AuditSSLService inspects the TLS certificate and cipher suite for a single endpoint.
func AuditSSLService(ip string, port int, timeout time.Duration, hostname ...string) core.SslFinding {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	finding := core.SslFinding{
		IP:       ip,
		Port:     port,
		Severity: "INFO",
	}

	sniHost := ip
	if len(hostname) > 0 && hostname[0] != "" {
		sniHost = hostname[0]
	}

	// Attempt connection with TLS InsecureSkipVerify and SNI
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sniHost,
		MinVersion:         tls.VersionTLS10,
	})

	if err != nil {
		finding.Notes = []string{fmt.Sprintf("TLS bağlantısı kurulamadı: %v", err)}
		return finding
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		finding.Notes = []string{"Sunucudan TLS sertifikası alınamadı"}
		return finding
	}

	cert := state.PeerCertificates[0]
	now := time.Now()

	expiryStr := cert.NotAfter.Format("2006-01-02")
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
	isExpired := now.After(cert.NotAfter)

	// Check self-signed
	isSelfSigned := cert.Issuer.CommonName == cert.Subject.CommonName || cert.AuthorityKeyId == nil

	var notes []string
	severity := "LOW"

	if isExpired {
		notes = append(notes, fmt.Sprintf("Sertifika süresi dolmuş! (%s)", expiryStr))
		severity = "HIGH"
	} else if daysLeft <= 30 {
		notes = append(notes, fmt.Sprintf("Sertifika yakında dolacak (%d gün kaldı)", daysLeft))
		if severity != "HIGH" {
			severity = "MEDIUM"
		}
	}

	if isSelfSigned {
		notes = append(notes, "Self-Signed (Öz İmzalı) Sertifika")
		if severity == "LOW" {
			severity = "MEDIUM"
		}
	}

	// Test weak SSL/TLS protocols
	var weakProtos []string
	protocols := []struct {
		name string
		ver  uint16
	}{
		{"SSLv3", tls.VersionSSL30},
		{"TLSv1.0", tls.VersionTLS10},
		{"TLSv1.1", tls.VersionTLS11},
	}

	for _, p := range protocols {
		testConn, err := tls.DialWithDialer(&net.Dialer{Timeout: 1500 * time.Millisecond}, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         ip,
			MinVersion:         p.ver,
			MaxVersion:         p.ver,
		})
		if err == nil {
			_ = testConn.Close()
			weakProtos = append(weakProtos, p.name)
			notes = append(notes, fmt.Sprintf("Zayıf protokol destekleniyor: %s", p.name))
			severity = "HIGH"
		}
	}

	// SANs (Subject Alternative Names)
	var sans []string
	for _, dnsName := range cert.DNSNames {
		sans = append(sans, dnsName)
	}

	subject := cert.Subject.CommonName
	if subject == "" && len(cert.Subject.Organization) > 0 {
		subject = cert.Subject.Organization[0]
	}

	issuer := cert.Issuer.CommonName
	if issuer == "" && len(cert.Issuer.Organization) > 0 {
		issuer = cert.Issuer.Organization[0]
	}

	if len(notes) == 0 {
		notes = append(notes, "Geçerli / Güvenli Sertifika")
	}

	return core.SslFinding{
		IP:              ip,
		Port:            port,
		Subject:         subject,
		Issuer:          issuer,
		SANs:            sans,
		ExpiryDate:      expiryStr,
		DaysUntilExpiry: daysLeft,
		IsExpired:       isExpired,
		IsSelfSigned:    isSelfSigned,
		WeakProtocols:   weakProtos,
		Severity:        severity,
		Notes:           notes,
	}
}

// AuditSSLMultiple scans all SSL-enabled services concurrently.
func AuditSSLMultiple(services []core.ServiceDetail, timeout time.Duration, outputFile string) ([]core.SslFinding, error) {
	var targets []core.ServiceDetail
	for _, s := range services {
		if s.SSLEnabled || s.Port == 443 || s.Port == 8443 || s.ServiceName == "https" || strings.Contains(s.ServiceName, "ssl") {
			targets = append(targets, s)
		}
	}

	if len(targets) == 0 {
		return nil, nil
	}

	core.LogInfo("SSL/TLS Denetimi başlatılıyor (%d TLS servisi)...", len(targets))
	var findings []core.SslFinding

	for _, t := range targets {
		f := AuditSSLService(t.IP, t.Port, timeout, t.Hostname)
		findings = append(findings, f)
		if f.IsExpired || f.IsSelfSigned || len(f.WeakProtocols) > 0 {
			core.LogWarning("SSL/TLS Riski (%s:%d): %s", f.IP, f.Port, strings.Join(f.Notes, " | "))
		} else if f.Subject != "" {
			core.LogSuccess("SSL Sertifikası okundu (%s:%d): CN=%s (Kalan gün: %d)", f.IP, f.Port, f.Subject, f.DaysUntilExpiry)
		} else {
			core.LogInfo("SSL/TLS Kontrol (%s:%d): %s", f.IP, f.Port, strings.Join(f.Notes, " | "))
		}
	}

	if outputFile != "" {
		_ = core.SaveSslFindings(findings, outputFile)
	}

	return findings, nil
}

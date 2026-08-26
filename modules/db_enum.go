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

// AuditDatabaseService tests various database protocols for unauthenticated access or default credentials.
func AuditDatabaseService(ip string, port int, serviceName string, timeout time.Duration) core.DbFinding {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	finding := core.DbFinding{
		IP:       ip,
		Port:     port,
		DbType:   serviceName,
		Severity: "INFO",
	}

	switch {
	case serviceName == "redis" || port == 6379:
		finding.DbType = "redis"
		auditRedis(addr, &finding, timeout)

	case serviceName == "mongodb" || port == 27017:
		finding.DbType = "mongodb"
		auditMongoDB(addr, &finding, timeout)

	case serviceName == "memcached" || port == 11211:
		finding.DbType = "memcached"
		auditMemcached(addr, &finding, timeout)

	case serviceName == "mysql" || port == 3306:
		finding.DbType = "mysql"
		auditMySQLHandshake(addr, &finding, timeout)

	case serviceName == "postgresql" || port == 5432:
		finding.DbType = "postgresql"
		auditPostgresHandshake(addr, &finding, timeout)

	case serviceName == "mssql" || port == 1433:
		finding.DbType = "mssql"
		auditMSSQLHandshake(addr, &finding, timeout)

	case serviceName == "elasticsearch" || port == 9200:
		finding.DbType = "elasticsearch"
		auditElasticsearch(ip, port, &finding, timeout)
	}

	return finding
}

func auditRedis(addr string, f *core.DbFinding, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	// Send INFO command without AUTH
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("INFO\r\n"))

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, errRead := conn.Read(buf)

	if errRead == nil && n > 0 {
		res := string(buf[:n])
		if strings.Contains(res, "redis_version") {
			f.AnonAccess = true
			f.Severity = "CRITICAL"
			f.Notes = append(f.Notes, "REDIS AUTH OLMADAN TAM ERİŞİLEBİLİR! (NO AUTH UNPROTECTED)")

			// Extract version
			for _, line := range strings.Split(res, "\r\n") {
				if strings.HasPrefix(line, "redis_version:") {
					f.Version = strings.TrimPrefix(line, "redis_version:")
					break
				}
			}
		} else if strings.Contains(res, "NOAUTH") {
			f.Notes = append(f.Notes, "Redis şifre korumalı (AUTH gerekiyor)")
		}
	}
}

func auditMemcached(addr string, f *core.DbFinding, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("stats\r\n"))

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, errRead := conn.Read(buf)

	if errRead == nil && n > 0 {
		res := string(buf[:n])
		if strings.Contains(res, "STAT version") {
			f.AnonAccess = true
			f.Severity = "CRITICAL"
			f.Notes = append(f.Notes, "MEMCACHED KİMLİK DOĞRULAMASIZ ERİŞİLEBİLİR!")

			for _, line := range strings.Split(res, "\r\n") {
				if strings.HasPrefix(line, "STAT version ") {
					f.Version = strings.TrimPrefix(line, "STAT version ")
					break
				}
			}
		}
	}
}

func auditMongoDB(addr string, f *core.DbFinding, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	// MongoDB Wire Protocol isMaster / buildInfo Request
	isMasterMsg := []byte{
		0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69,
		0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x13,
		0x00, 0x00, 0x00, 0x10, 0x69, 0x73, 0x4d, 0x61,
		0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00,
	}

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(isMasterMsg)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, errRead := conn.Read(buf)

	if errRead == nil && n > 20 {
		if strings.Contains(string(buf[:n]), "ismaster") || strings.Contains(string(buf[:n]), "maxWireVersion") {
			f.AnonAccess = true
			f.Severity = "CRITICAL"
			f.Notes = append(f.Notes, "MONGODB UNPROTECTED AÇIK! (Kimlik doğrulaması yok)")
		}
	}
}

func auditMySQLHandshake(addr string, f *core.DbFinding, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, errRead := conn.Read(buf)

	if errRead == nil && n > 5 {
		// MySQL Handshake Packet contains version string
		verBytes := buf[5:]
		idx := 0
		for idx < len(verBytes) && verBytes[idx] != 0 {
			idx++
		}
		if idx > 0 {
			f.Version = string(verBytes[:idx])
			f.Notes = append(f.Notes, fmt.Sprintf("MySQL Versiyonu: %s", f.Version))
		}
	}
}

func auditPostgresHandshake(addr string, f *core.DbFinding, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	// PostgreSQL Startup Message
	startupMsg := []byte{
		0x00, 0x00, 0x00, 0x24, // Length
		0x00, 0x03, 0x00, 0x00, // Protocol 3.0
		'u', 's', 'e', 'r', 0x00, 'p', 'o', 's', 't', 'g', 'r', 'e', 's', 0x00,
		'd', 'a', 't', 'a', 'b', 'a', 's', 'e', 0x00, 'p', 'o', 's', 't', 'g', 'r', 'e', 's', 0x00,
		0x00,
	}

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(startupMsg)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, errRead := conn.Read(buf)

	if errRead == nil && n > 0 {
		if buf[0] == 'R' { // Authentication request
			authType := uint32(buf[5])
			if authType == 0 { // Auth OK (No password required!)
				f.AnonAccess = true
				f.Severity = "CRITICAL"
				f.Notes = append(f.Notes, "POSTGRESQL TRUST AUTHENTICATION (Şifresiz Giriş Başarılı!)")
			}
		}
	}
}

func auditMSSQLHandshake(addr string, f *core.DbFinding, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	// MSSQL Pre-Login Packet
	prelogin := []byte{
		0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20,
		0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
		0x00, 0x22, 0x00, 0x04, 0xff, 0x08, 0x00, 0x01,
		0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(prelogin)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, errRead := conn.Read(buf)

	if errRead == nil && n > 8 && buf[0] == 0x04 { // Tabular Data Stream Response
		f.Notes = append(f.Notes, "MSSQL Sunucusu Aktif")
	}
}

func auditElasticsearch(ip string, port int, f *core.DbFinding, timeout time.Duration) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: SpecterRecon/1.2\r\n\r\n"))

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	buf := make([]byte, 4096)
	n, errRead := reader.Read(buf)

	if errRead == nil && n > 0 {
		res := string(buf[:n])
		if strings.Contains(res, "you_know_for_search") || strings.Contains(res, "cluster_name") {
			f.AnonAccess = true
			f.Severity = "HIGH"
			f.Notes = append(f.Notes, "ELASTICSEARCH KİMLİK DOĞRULAMASIZ ERİŞİLEBİLİR!")
		}
	}
}

// AuditDatabaseMultiple scans all database services found across target hosts.
func AuditDatabaseMultiple(services []core.ServiceDetail, timeout time.Duration, outputFile string) ([]core.DbFinding, error) {
	dbPorts := map[int]string{
		3306:  "mysql",
		1433:  "mssql",
		5432:  "postgresql",
		27017: "mongodb",
		6379:  "redis",
		11211: "memcached",
		9200:  "elasticsearch",
	}

	var targets []core.ServiceDetail
	for _, s := range services {
		if _, ok := dbPorts[s.Port]; ok || strings.Contains(s.ServiceName, "sql") || s.ServiceName == "redis" || s.ServiceName == "mongodb" || s.ServiceName == "memcached" {
			targets = append(targets, s)
		}
	}

	if len(targets) == 0 {
		return nil, nil
	}

	core.LogInfo("Veritabanı Güvenlik Denetimi (Redis, Mongo, Postgres, MySQL, Memcached) başlatılıyor (%d DB servisi)...", len(targets))
	var findings []core.DbFinding

	for _, t := range targets {
		dbType := t.ServiceName
		if dbType == "" || dbType == "unknown" {
			if mapped, ok := dbPorts[t.Port]; ok {
				dbType = mapped
			}
		}

		f := AuditDatabaseService(t.IP, t.Port, dbType, timeout)
		if f.DbType != "" {
			findings = append(findings, f)
			if f.AnonAccess || f.DefaultCreds {
				core.LogWarning("🚨 CRITICAL VERİTABANI RİSKİ (%s:%d - %s): %s", f.IP, f.Port, f.DbType, strings.Join(f.Notes, " | "))
			} else {
				core.LogInfo("Veritabanı Denetim (%s:%d - %s): %s", f.IP, f.Port, f.DbType, strings.Join(f.Notes, " | "))
			}
		}
	}

	if outputFile != "" {
		_ = core.SaveDbFindings(findings, outputFile)
	}

	return findings, nil
}

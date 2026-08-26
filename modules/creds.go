package modules

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

type CredPair struct {
	User string
	Pass string
}

var DefaultCredentialMap = map[string][]CredPair{
	"ftp": {
		{"anonymous", "anonymous@specter.local"},
		{"admin", "admin"},
		{"root", "root"},
	},
	"ssh": {
		{"root", "root"},
		{"root", "toor"},
		{"admin", "admin"},
		{"pi", "raspberry"},
	},
	"mysql": {
		{"root", ""},
		{"root", "root"},
		{"root", "mysql"},
	},
	"redis": {
		{"", ""}, // No auth
	},
	"http": {
		{"admin", "admin"},
		{"admin", "password"},
		{"user", "user"},
	},
}

// AuditDefaultCredentials tests a service for standard default credentials.
func AuditDefaultCredentials(ip string, port int, protocol string, timeout time.Duration) []core.CredFinding {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	protoKey := strings.ToLower(protocol)
	creds, ok := DefaultCredentialMap[protoKey]
	if !ok {
		if port == 21 {
			creds = DefaultCredentialMap["ftp"]
			protoKey = "ftp"
		} else if port == 22 {
			creds = DefaultCredentialMap["ssh"]
			protoKey = "ssh"
		} else if port == 3306 {
			creds = DefaultCredentialMap["mysql"]
			protoKey = "mysql"
		} else if port == 80 || port == 443 || port == 8080 {
			creds = DefaultCredentialMap["http"]
			protoKey = "http"
		} else {
			return nil
		}
	}

	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	var findings []core.CredFinding

	for _, pair := range creds {
		success := false
		switch protoKey {
		case "ftp":
			success = testFTPCred(addr, pair.User, pair.Pass, timeout)
		case "http":
			success = testHTTPBasicCred(ip, port, pair.User, pair.Pass, timeout)
		}

		if success {
			finding := core.CredFinding{
				IP:       ip,
				Port:     port,
				Protocol: protoKey,
				Username: pair.User,
				Password: pair.Pass,
				Severity: "CRITICAL",
			}
			findings = append(findings, finding)
			core.LogWarning("🚨 CRITICAL VARSAYILAN KREDİ TESPİT EDİLDİ (%s:%d - %s): %s / '%s'", ip, port, protoKey, pair.User, pair.Pass)
		}
	}

	return findings
}

func testFTPCred(addr string, user string, pass string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	reader := bufio.NewReader(conn)
	_, _ = reader.ReadString('\n')

	_ = conn.SetWriteDeadline(time.Now().Add(1500 * time.Millisecond))
	_, _ = conn.Write([]byte("USER " + user + "\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	respUser, _ := reader.ReadString('\n')

	if strings.HasPrefix(respUser, "331") || strings.HasPrefix(respUser, "230") {
		if strings.HasPrefix(respUser, "230") {
			return true // No password required
		}
		_, _ = conn.Write([]byte("PASS " + pass + "\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		respPass, _ := reader.ReadString('\n')
		return strings.HasPrefix(respPass, "230")
	}
	return false
}

func testHTTPBasicCred(ip string, port int, user string, pass string, timeout time.Duration) bool {
	proto := "http"
	if port == 443 || port == 8443 {
		proto = "https"
	}
	targetURL := fmt.Sprintf("%s://%s:%d/admin", proto, ip, port)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: timeout}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false
	}
	req.SetBasicAuth(user, pass)

	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		return resp.StatusCode == 200
	}
	return false
}

// AuditDefaultCredentialsMultiple scans all target services for default credentials.
func AuditDefaultCredentialsMultiple(services []core.ServiceDetail, timeout time.Duration, outputFile string) ([]core.CredFinding, error) {
	if len(services) == 0 {
		return nil, nil
	}

	core.LogInfo("Varsayılan Kredi (Default Credential) Tespiti başlatılıyor (%d servis)...", len(services))
	var allFindings []core.CredFinding

	for _, s := range services {
		findings := AuditDefaultCredentials(s.IP, s.Port, s.ServiceName, timeout)
		allFindings = append(allFindings, findings...)
	}

	if outputFile != "" {
		_ = core.SaveCredFindings(allFindings, outputFile)
	}

	return allFindings, nil
}

package modules

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

// AuditHTTPService performs full HTTP security configuration checks on a single service.
func AuditHTTPService(ip string, port int, isSSL bool, timeout time.Duration) core.HttpAuditFinding {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	proto := "http"
	if isSSL {
		proto = "https"
	}
	targetURL := fmt.Sprintf("%s://%s:%d/", proto, ip, port)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         ip,
			MinVersion:         tls.VersionTLS10,
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return core.HttpAuditFinding{URL: targetURL, IP: ip, Port: port}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SpecterRecon/1.2")

	resp, err := client.Do(req)
	if err != nil {
		return core.HttpAuditFinding{URL: targetURL, IP: ip, Port: port}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	_ = string(bodyBytes)

	finding := core.HttpAuditFinding{
		URL:          targetURL,
		IP:           ip,
		Port:         port,
		ServerHeader: resp.Header.Get("Server"),
		Severity:     "LOW",
	}

	// 1. Missing Security Headers
	expectedHeaders := map[string]string{
		"Strict-Transport-Security": "HSTS Eksik (Man-in-the-Middle riski)",
		"Content-Security-Policy":   "CSP Header Eksik (XSS riski)",
		"X-Frame-Options":           "X-Frame-Options Eksik (Clickjacking riski)",
		"X-Content-Type-Options":    "X-Content-Type-Options Eksik (MIME Sniffing riski)",
		"Referrer-Policy":           "Referrer-Policy Eksik",
	}

	for header, label := range expectedHeaders {
		if isSSL || header != "Strict-Transport-Security" { // HSTS only relevant for SSL
			if resp.Header.Get(header) == "" {
				finding.MissingHeaders = append(finding.MissingHeaders, label)
			}
		}
	}

	// 2. Dangerous HTTP Methods
	methodsToTest := []string{"TRACE", "PUT", "DELETE"}
	for _, m := range methodsToTest {
		mReq, err := http.NewRequest(m, targetURL, nil)
		if err == nil {
			mResp, err := client.Do(mReq)
			if err == nil {
				_ = mResp.Body.Close()
				if mResp.StatusCode == 200 || mResp.StatusCode == 204 {
					finding.DangerousMethods = append(finding.DangerousMethods, m)
					finding.Severity = "HIGH"
				}
			}
		}
	}

	// 3. CORS Misconfiguration Check
	corsReq, err := http.NewRequest("GET", targetURL, nil)
	if err == nil {
		corsReq.Header.Set("Origin", "https://evil-attacker.com")
		corsResp, err := client.Do(corsReq)
		if err == nil {
			_ = corsResp.Body.Close()
			acaOrigin := corsResp.Header.Get("Access-Control-Allow-Origin")
			acaCreds := corsResp.Header.Get("Access-Control-Allow-Credentials")
			if acaOrigin == "*" {
				finding.CORSIssues = append(finding.CORSIssues, "Access-Control-Allow-Origin: * (Tüm domainlere açık)")
				if finding.Severity != "HIGH" {
					finding.Severity = "MEDIUM"
				}
			} else if acaOrigin == "https://evil-attacker.com" {
				if acaCreds == "true" {
					finding.CORSIssues = append(finding.CORSIssues, "CORS Wildcard/Reflected Origin + Credentials: true (KRİTİK VULN)")
					finding.Severity = "CRITICAL"
				} else {
					finding.CORSIssues = append(finding.CORSIssues, "Reflected Origin CORS (evil-attacker.com kabul edildi)")
					if finding.Severity != "HIGH" {
						finding.Severity = "MEDIUM"
					}
				}
			}
		}
	}

	// 4. GraphQL Introspection Check
	gqlURL := fmt.Sprintf("%s://%s:%d/graphql", proto, ip, port)
	gqlReq, err := http.NewRequest("POST", gqlURL, strings.NewReader(`{"query":"{__schema{types{name}}}"}`))
	if err == nil {
		gqlReq.Header.Set("Content-Type", "application/json")
		gqlResp, err := client.Do(gqlReq)
		if err == nil {
			gqlBody, _ := io.ReadAll(io.LimitReader(gqlResp.Body, 4096))
			_ = gqlResp.Body.Close()
			if strings.Contains(string(gqlBody), "__schema") {
				finding.GraphQLOpen = true
				if finding.Severity == "LOW" {
					finding.Severity = "MEDIUM"
				}
			}
		}
	}

	// 5. Robots.txt Check
	robotsURL := fmt.Sprintf("%s://%s:%d/robots.txt", proto, ip, port)
	rReq, err := http.NewRequest("GET", robotsURL, nil)
	if err == nil {
		rResp, err := client.Do(rReq)
		if err == nil {
			rBody, _ := io.ReadAll(io.LimitReader(rResp.Body, 8192))
			_ = rResp.Body.Close()
			if rResp.StatusCode == 200 && strings.Contains(string(rBody), "Disallow:") {
				finding.RobotsFound = true
				lines := strings.Split(string(rBody), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(strings.ToLower(line), "disallow:") {
						parts := strings.SplitN(line, ":", 2)
						if len(parts) > 1 {
							path := strings.TrimSpace(parts[1])
							if path != "" && path != "/" {
								finding.RobotsPaths = append(finding.RobotsPaths, path)
							}
						}
					}
				}
			}
		}
	}

	// 6. Cookie Security Check
	for _, cookie := range resp.Cookies() {
		var issues []string
		if !cookie.HttpOnly {
			issues = append(issues, fmt.Sprintf("%s (HttpOnly eksik)", cookie.Name))
		}
		if isSSL && !cookie.Secure {
			issues = append(issues, fmt.Sprintf("%s (Secure eksik)", cookie.Name))
		}
		if len(issues) > 0 {
			finding.CookieIssues = append(finding.CookieIssues, strings.Join(issues, ", "))
		}
	}

	if len(finding.MissingHeaders) > 0 || len(finding.DangerousMethods) > 0 || len(finding.CORSIssues) > 0 || finding.GraphQLOpen {
		if finding.Severity == "LOW" && len(finding.MissingHeaders) > 2 {
			finding.Severity = "MEDIUM"
		}
	}

	return finding
}

// AuditHTTPMultiple runs HTTP security checks on all identified web services.
func AuditHTTPMultiple(services []core.ServiceDetail, timeout time.Duration, outputFile string) ([]core.HttpAuditFinding, error) {
	var targets []core.ServiceDetail
	for _, s := range services {
		if s.ServiceName == "http" || s.ServiceName == "https" || s.SSLEnabled || s.Port == 80 || s.Port == 443 || s.Port == 8080 || s.Port == 8443 {
			targets = append(targets, s)
		}
	}

	if len(targets) == 0 {
		return nil, nil
	}

	core.LogInfo("HTTP Güvenlik Denetimi (Security Headers, CORS, GraphQL, Methods) başlatılıyor (%d web servisi)...", len(targets))
	var findings []core.HttpAuditFinding

	for _, t := range targets {
		f := AuditHTTPService(t.IP, t.Port, t.SSLEnabled, timeout)
		findings = append(findings, f)

		msg := fmt.Sprintf("%s — Eksik Header: %d", f.URL, len(f.MissingHeaders))
		if len(f.DangerousMethods) > 0 {
			msg += fmt.Sprintf(" | Tehlikeli Metod: %s", strings.Join(f.DangerousMethods, ","))
		}
		if f.GraphQLOpen {
			msg += " | GraphQL Open"
		}
		if len(f.CORSIssues) > 0 {
			msg += " | CORS Risk"
		}

		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			core.LogWarning("HTTP Güvenlik Uyarısı (%s): %s", f.Severity, msg)
		} else {
			core.LogInfo("HTTP Denetim (%s): %s", f.URL, msg)
		}
	}

	if outputFile != "" {
		_ = core.SaveHttpAuditFindings(findings, outputFile)
	}

	return findings, nil
}

package modules

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WebVulnFinding struct {
	URL         string `json:"url"`
	VulnType    string `json:"vuln_type"` // SQLi, XSS, OpenRedirect, SSRF
	Parameter   string `json:"parameter,omitempty"`
	Payload     string `json:"payload"`
	Severity    string `json:"severity"` // CRITICAL, HIGH, MEDIUM
	Evidence    string `json:"evidence"`
	Description string `json:"description"`
}

// AuditWebVulnerabilities performs lightweight, non-destructive web vulnerability checks on a target URL.
func AuditWebVulnerabilities(targetURL string, timeout time.Duration) []WebVulnFinding {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	u, err := url.Parse(targetURL)
	if err != nil || u.RawQuery == "" {
		return nil
	}

	queryParams := u.Query()
	if len(queryParams) == 0 {
		return nil
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't auto-follow redirects for Open Redirect test
		},
	}

	var findings []WebVulnFinding

	for param := range queryParams {
		// 1. Reflected XSS Test
		xssPayload := `"><specterxss123>`
		testParams := copyURLValues(queryParams)
		testParams.Set(param, xssPayload)
		u.RawQuery = testParams.Encode()

		req, _ := http.NewRequest("GET", u.String(), nil)
		req.Header.Set("User-Agent", "SpecterRecon/1.2")
		resp, err := client.Do(req)
		if err == nil {
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
			_ = resp.Body.Close()
			if strings.Contains(string(bodyBytes), xssPayload) {
				findings = append(findings, WebVulnFinding{
					URL:         targetURL,
					VulnType:    "Reflected XSS",
					Parameter:   param,
					Payload:     xssPayload,
					Severity:    "HIGH",
					Evidence:    fmt.Sprintf("XSS payload '%s' HTML yanıtında filtresiz olduğu gibi yansıdı", xssPayload),
					Description: "Parametre değeri HTML çıktısında temizlenmeden yansıtılıyor (XSS zafiyeti)",
				})
			}
		}

		// 2. SQL Error-Based Test
		sqliPayload := `' OR '1'='1`
		testParams = copyURLValues(queryParams)
		testParams.Set(param, sqliPayload)
		u.RawQuery = testParams.Encode()

		reqSQL, _ := http.NewRequest("GET", u.String(), nil)
		reqSQL.Header.Set("User-Agent", "SpecterRecon/1.2")
		respSQL, errSQL := client.Do(reqSQL)
		if errSQL == nil {
			bodyBytes, _ := io.ReadAll(io.LimitReader(respSQL.Body, 65536))
			_ = respSQL.Body.Close()
			bodyLower := strings.ToLower(string(bodyBytes))

			sqlErrors := []string{
				"you have an error in your sql syntax",
				"warning: mysql",
				"unclosed quotation mark after the character string",
				"pg_query(): query failed",
				"sqlite3::query(): unable to prepare statement",
				"oracle error",
			}

			for _, sqlErr := range sqlErrors {
				if strings.Contains(bodyLower, sqlErr) {
					findings = append(findings, WebVulnFinding{
						URL:         targetURL,
						VulnType:    "SQL Injection (Error-Based)",
						Parameter:   param,
						Payload:     sqliPayload,
						Severity:    "CRITICAL",
						Evidence:    fmt.Sprintf("SQL hatası yansıdı: '%s'", sqlErr),
						Description: "SQL sorgusu girdiyi doğrudan birleştiriyor (SQL Injection zafiyeti)",
					})
					break
				}
			}
		}

		// 3. Open Redirect Test (if param name looks like url, redirect, next, dest, etc.)
		paramLower := strings.ToLower(param)
		if strings.Contains(paramLower, "url") || strings.Contains(paramLower, "redirect") || strings.Contains(paramLower, "next") || strings.Contains(paramLower, "dest") || strings.Contains(paramLower, "return") {
			redirectPayload := "https://evil-attacker.com"
			testParams = copyURLValues(queryParams)
			testParams.Set(param, redirectPayload)
			u.RawQuery = testParams.Encode()

			reqRedir, _ := http.NewRequest("GET", u.String(), nil)
			respRedir, errRedir := client.Do(reqRedir)
			if errRedir == nil {
				_ = respRedir.Body.Close()
				loc := respRedir.Header.Get("Location")
				if strings.HasPrefix(loc, redirectPayload) {
					findings = append(findings, WebVulnFinding{
						URL:         targetURL,
						VulnType:    "Open Redirect",
						Parameter:   param,
						Payload:     redirectPayload,
						Severity:    "MEDIUM",
						Evidence:    fmt.Sprintf("HTTP %d Redirect -> %s", respRedir.StatusCode, loc),
						Description: "Harici domaine yönlendirme doğrulama yapılmadan kabul ediliyor",
					})
				}
			}
		}
	}

	return findings
}

func copyURLValues(v url.Values) url.Values {
	cp := make(url.Values)
	for k, list := range v {
		cp[k] = append([]string(nil), list...)
	}
	return cp
}

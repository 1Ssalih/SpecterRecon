package modules

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/specter-recon/recon-tool/core"
)

type ServiceRegexRule struct {
	Pattern     *regexp.Regexp
	ServiceName string
	Description string
	ExtractVer  func(matches []string) string
	Priority    int
	Confidence  int
}

var ServiceRegexRules = []ServiceRegexRule{
	// OpenSSH & SSH
	{
		Pattern:     regexp.MustCompile(`(?i)SSH-[\d\.]+-OpenSSH[_\s]([\w\.\-p]+)`),
		ServiceName: "ssh",
		Description: "OpenSSH",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    1,
		Confidence:  95,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)SSH-[\d\.]+-Dropbear[_\s]([\d\.]+)`),
		ServiceName: "ssh",
		Description: "Dropbear SSH",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    1,
		Confidence:  90,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)SSH-[\d\.]+-libssh[_\s]([\w\.\-]+)`),
		ServiceName: "ssh",
		Description: "libssh",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    2,
		Confidence:  90,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)SSH-[\d\.]+-([^\r\n]+)`),
		ServiceName: "ssh",
		Description: "SSH Server",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    10,
		Confidence:  75,
	},
	// HTTP Servers & Web Frameworks
	{
		Pattern:     regexp.MustCompile(`(?i)Microsoft-HTTPAPI/([\d\.]+)`),
		ServiceName: "http",
		Description: "Microsoft HTTPAPI (WinRM / IIS)",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    5,
		Confidence:  90,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)Microsoft-IIS/([\d\.]+)`),
		ServiceName: "http",
		Description: "Microsoft IIS",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    5,
		Confidence:  90,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)Apache(?:/([\d\.]+))?`),
		ServiceName: "http",
		Description: "Apache HTTP Server",
		ExtractVer: func(m []string) string {
			if len(m) > 1 {
				return m[1]
			}
			return ""
		},
		Priority:   10,
		Confidence: 85,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)nginx(?:/([\d\.]+))?`),
		ServiceName: "http",
		Description: "nginx",
		ExtractVer: func(m []string) string {
			if len(m) > 1 {
				return m[1]
			}
			return ""
		},
		Priority:   10,
		Confidence: 85,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)lighttpd(?:/([\d\.]+))?`),
		ServiceName: "http",
		Description: "lighttpd",
		ExtractVer: func(m []string) string {
			if len(m) > 1 {
				return m[1]
			}
			return ""
		},
		Priority:   10,
		Confidence: 85,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)Werkzeug/([\d\.]+)`),
		ServiceName: "http",
		Description: "Werkzeug (Python)",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    15,
		Confidence:  80,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)PHP/([\d\.]+)`),
		ServiceName: "http",
		Description: "PHP",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    20,
		Confidence:  80,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)Tomcat/([\d\.]+)`),
		ServiceName: "http",
		Description: "Apache Tomcat",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    10,
		Confidence:  85,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)Spring-Boot(?:/([\d\.]+))?|Whitelabel Error Page|X-Application-Context`),
		ServiceName: "http",
		Description: "Spring Boot",
		ExtractVer: func(m []string) string {
			if len(m) > 1 {
				return m[1]
			}
			return ""
		},
		Priority:   5,
		Confidence: 85,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)Next\.js(?:/([\d\.]+))?|__NEXT_DATA__`),
		ServiceName: "http",
		Description: "Next.js",
		ExtractVer: func(m []string) string {
			if len(m) > 1 {
				return m[1]
			}
			return ""
		},
		Priority:   5,
		Confidence: 85,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)Django(?:/([\d\.]+))?`),
		ServiceName: "http",
		Description: "Django",
		ExtractVer: func(m []string) string {
			if len(m) > 1 {
				return m[1]
			}
			return ""
		},
		Priority:   5,
		Confidence: 85,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)Express(?:/([\d\.]+))?`),
		ServiceName: "http",
		Description: "Express (Node.js)",
		ExtractVer: func(m []string) string {
			if len(m) > 1 {
				return m[1]
			}
			return ""
		},
		Priority:   15,
		Confidence: 80,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)ASP\.NET(?:\s+Version:([\d\.]+))?`),
		ServiceName: "http",
		Description: "ASP.NET",
		ExtractVer: func(m []string) string {
			if len(m) > 1 {
				return m[1]
			}
			return ""
		},
		Priority:   15,
		Confidence: 80,
	},
	// FTP
	{
		Pattern:     regexp.MustCompile(`(?i)vsftpd[\s/]?([\d\.]+)`),
		ServiceName: "ftp",
		Description: "vsftpd",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    1,
		Confidence:  90,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)ProFTPD[\s/]?([\d\.]+)`),
		ServiceName: "ftp",
		Description: "ProFTPD",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    1,
		Confidence:  90,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)220[- ].*FileZilla Server ([\d\.]+)`),
		ServiceName: "ftp",
		Description: "FileZilla Server",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    1,
		Confidence:  90,
	},
	// Databases
	{
		Pattern:     regexp.MustCompile(`(?i)([\d\.\-\w]+)-MariaDB`),
		ServiceName: "mysql",
		Description: "MariaDB",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    1,
		Confidence:  95,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)redis_version:([\d\.]+)`),
		ServiceName: "redis",
		Description: "Redis",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    1,
		Confidence:  95,
	},
	{
		Pattern:     regexp.MustCompile(`(?i)VERSION\s+([\d\.]+)`),
		ServiceName: "memcached",
		Description: "Memcached",
		ExtractVer:  func(m []string) string { return m[1] },
		Priority:    1,
		Confidence:  95,
	},
}

// SanitizeBanner removes non-printable, control, and invalid binary characters from banner strings.
func SanitizeBanner(s string) string {
	if s == "" {
		return ""
	}
	var sb strings.Builder
	for _, r := range s {
		// Keep only standard printable ASCII and valid printable letters/digits
		if (r >= 32 && r <= 126) || (r > 127 && unicode.IsLetter(r)) || (r > 127 && unicode.IsDigit(r)) {
			sb.WriteRune(r)
		} else {
			sb.WriteByte(' ')
		}
	}
	cleaned := strings.Join(strings.Fields(sb.String()), " ")
	// If after cleaning, there are no letters or digits, discard leftover punctuation or binary remnants
	hasAlphaNum := false
	for _, r := range cleaned {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			hasAlphaNum = true
			break
		}
	}
	if !hasAlphaNum {
		return ""
	}
	return cleaned
}

// ParseMySQLHandshake parses the raw binary MySQL/MariaDB initial handshake packet.
func ParseMySQLHandshake(buf []byte) (serviceName, description, version, rawBanner string) {
	if len(buf) < 5 {
		return "", "", "", ""
	}
	// MySQL Handshake packet layout:
	// buf[0..2] = 3-byte payload length
	// buf[3]    = sequence id
	// buf[4]    = protocol version (usually 10 for MySQL 5.x/8.x/MariaDB)
	// buf[5..]  = null-terminated server version string
	protoVer := buf[4]
	if protoVer != 10 && protoVer != 9 {
		return "", "", "", ""
	}

	nullIdx := -1
	for i := 5; i < len(buf); i++ {
		if buf[i] == 0 {
			nullIdx = i
			break
		}
	}

	var verStr string
	if nullIdx != -1 {
		verStr = string(buf[5:nullIdx])
	} else if len(buf) > 5 {
		verStr = string(buf[5:])
	}
	verStr = SanitizeBanner(verStr)
	if verStr == "" {
		return "", "", "", ""
	}

	serviceName = "mysql"
	description = "MySQL Database Server"
	version = verStr

	if strings.Contains(strings.ToLower(verStr), "mariadb") {
		description = "MariaDB Database Server"
		mariaMatch := regexp.MustCompile(`^([\d\.]+)-MariaDB`).FindStringSubmatch(verStr)
		if len(mariaMatch) > 1 {
			version = mariaMatch[1]
		}
	} else {
		mysqlMatch := regexp.MustCompile(`^([\d\.]+)`).FindStringSubmatch(verStr)
		if len(mysqlMatch) > 1 {
			version = mysqlMatch[1]
		}
	}

	rawBanner = fmt.Sprintf("MySQL Handshake (Protocol %d, Version %s)", protoVer, verStr)
	return serviceName, description, version, rawBanner
}

// ParseBinaryProtocolBanner inspects raw binary socket responses for known binary protocols (NetBIOS, FSSO, VNC, etc.).
func ParseBinaryProtocolBanner(port int, buf []byte) (serviceName, description, version, rawBanner string, handled bool) {
	if len(buf) == 0 {
		return "", "", "", "", false
	}

	// 1. MySQL Handshake
	if port == 3306 || (len(buf) >= 5 && (buf[4] == 10 || buf[4] == 9)) {
		sName, sDesc, sVer, myBanner := ParseMySQLHandshake(buf)
		if sName != "" {
			return sName, sDesc, sVer, myBanner, true
		}
	}

	// 2. NetBIOS Session Service (Port 139 / 445 / Raw SMB)
	if port == 139 || (len(buf) >= 4 && (buf[0] == 0x82 || buf[0] == 0x83 || buf[0] == 0x80 || buf[0] == 0x81)) {
		return "netbios-ssn", "NetBIOS Session Service", "", "NetBIOS Session Service (SMB Transport)", true
	}

	// 3. Fortinet FSSO (Single Sign-On Agent / Collector)
	bufStr := string(buf)
	if strings.Contains(bufStr, "FSSO") || strings.Contains(bufStr, "Fortinet") {
		ver := ""
		re := regexp.MustCompile(`FSSO\s+([\d\.]+)`)
		if m := re.FindStringSubmatch(bufStr); len(m) > 1 {
			ver = m[1]
		}
		raw := "Fortinet FSSO Service"
		if ver != "" {
			raw = fmt.Sprintf("Fortinet Single Sign-On (FSSO v%s)", ver)
		}
		return "fsso", "Fortinet Single Sign-On Agent", ver, raw, true
	}

	// 4. RFB / VNC Protocol (e.g. "RFB 003.008\n", "RFB 005.000")
	if strings.HasPrefix(bufStr, "RFB ") {
		ver := ""
		re := regexp.MustCompile(`RFB\s+([\d\.]+)`)
		if m := re.FindStringSubmatch(bufStr); len(m) > 1 {
			ver = m[1]
		}
		return "vnc", "VNC Remote Framebuffer", ver, SanitizeBanner(bufStr), true
	}

	// 5. Check if buffer is unprintable binary data
	printableCount := 0
	for _, b := range buf {
		if b >= 32 && b <= 126 {
			printableCount++
		}
	}
	ratio := float64(printableCount) / float64(len(buf))
	if ratio < 0.35 {
		return "", "", "", "[Binary Protocol Response]", true
	}

	return "", "", "", "", false
}

// ExtractVersionFromText extracts service and version from banner text using prioritized, confidence-rated regexes.
func ExtractVersionFromText(text string) (serviceName, description, version string) {
	sanitized := SanitizeBanner(text)
	if sanitized == "" {
		return "", "", ""
	}

	type matchCandidate struct {
		rule     ServiceRegexRule
		version  string
		priority int
		conf     int
	}

	var candidates []matchCandidate
	for _, rule := range ServiceRegexRules {
		matches := rule.Pattern.FindStringSubmatch(sanitized)
		if len(matches) > 0 {
			ver := ""
			if rule.ExtractVer != nil {
				ver = rule.ExtractVer(matches)
			}
			candidates = append(candidates, matchCandidate{
				rule:     rule,
				version:  SanitizeBanner(ver),
				priority: rule.Priority,
				conf:     rule.Confidence,
			})
		}
	}

	if len(candidates) == 0 {
		return "", "", ""
	}

	// Pick lowest priority (highest importance) then highest confidence
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.priority < best.priority {
			best = c
		} else if c.priority == best.priority && c.conf > best.conf {
			best = c
		}
	}

	return best.rule.ServiceName, best.rule.Description, best.version
}

// GrabRawSocketBanner connects to raw TCP socket and reads banner, handling binary protocols cleanly.
func GrabRawSocketBanner(ip string, port int, timeout time.Duration) (banner string, parsedSvc string, parsedDesc string, parsedVer string) {
	probeRes := GrabServiceBanner(ip, port, timeout)
	return probeRes.Banner, probeRes.ServiceName, probeRes.ServiceDesc, probeRes.Version
}

type HTTPProbeResult struct {
	IsHTTP        bool
	Server        string
	Title         string
	Technologies  []string
	DetectedTechs []string
	Banner        string
	WAFDetected   bool
	WAFName       string
}

// ProbeHTTPService checks if service is HTTP/HTTPS and extracts headers, title, and fingerprints body.
func ProbeHTTPService(ip string, port int, isSSL bool, timeout time.Duration, hostname ...string) HTTPProbeResult {
	proto := "http"
	if isSSL {
		proto = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", proto, ip, port)

	sniHost := ip
	if len(hostname) > 0 && hostname[0] != "" {
		sniHost = hostname[0]
	}

	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         sniHost,
			MinVersion:         tls.VersionTLS10,
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return HTTPProbeResult{}
	}
	if sniHost != "" {
		req.Host = sniHost
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SpecterRecon/0.8.0")

	resp, err := client.Do(req)
	if err != nil {
		return HTTPProbeResult{}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	bodyStr := string(bodyBytes)

	var allHeaders []string
	var serverHeader string
	detectedTechMap := make(map[string]bool)

	addTech := func(tech string) {
		clean := strings.ToLower(SanitizeBanner(tech))
		if clean != "" && !detectedTechMap[clean] {
			detectedTechMap[clean] = true
		}
	}

	// Favicon MMH3 hash detection
	if _, favTech := DetectFaviconTech(bodyStr, url, client); favTech != "" {
		addTech(favTech)
	}

	for k, vList := range resp.Header {
		kLower := strings.ToLower(k)
		if kLower == "server" || kLower == "x-powered-by" || kLower == "via" || kLower == "x-aspnet-version" || kLower == "x-aspnetmvc-version" || kLower == "x-generator" {
			for _, v := range vList {
				cleanVal := SanitizeBanner(v)
				if cleanVal != "" {
					allHeaders = append(allHeaders, cleanVal)
					if kLower == "server" && serverHeader == "" {
						serverHeader = cleanVal
					}
					vLower := strings.ToLower(cleanVal)
					if strings.Contains(vLower, "apache") {
						addTech("apache")
					}
					if strings.Contains(vLower, "nginx") {
						addTech("nginx")
					}
					if strings.Contains(vLower, "iis") || strings.Contains(vLower, "microsoft-iis") {
						addTech("iis")
					}
					if strings.Contains(vLower, "tomcat") {
						addTech("tomcat")
					}
					if strings.Contains(vLower, "php") {
						addTech("php")
					}
					if strings.Contains(vLower, "asp.net") {
						addTech("aspnet")
					}
					if strings.Contains(vLower, "express") {
						addTech("express")
					}
					if strings.Contains(vLower, "next.js") {
						addTech("nextjs")
					}
					if strings.Contains(vLower, "django") {
						addTech("django")
					}
					if strings.Contains(vLower, "ruby") || strings.Contains(vLower, "rails") || strings.Contains(vLower, "phusion passenger") {
						addTech("rails")
					}
					if strings.Contains(vLower, "kestrel") {
						addTech("aspnet")
					}
					if strings.Contains(vLower, "gunicorn") || strings.Contains(vLower, "uvicorn") || strings.Contains(vLower, "werkzeug") {
						addTech("django")
					}
				}
			}
		}
		if kLower == "set-cookie" {
			for _, cv := range vList {
				cvLower := strings.ToLower(cv)
				if strings.Contains(cvLower, "csrftoken") || strings.Contains(cvLower, "django") {
					addTech("django")
				}
				if strings.Contains(cvLower, "phpsessid") {
					addTech("php")
				}
				if strings.Contains(cvLower, "jsessionid") {
					addTech("tomcat")
				}
				if strings.Contains(cvLower, "asp.net_sessionid") {
					addTech("aspnet")
				}
				if strings.Contains(cvLower, "grafana_session") {
					addTech("grafana")
				}
				if strings.Contains(cvLower, "_gitlab_session") {
					addTech("gitlab")
				}
			}
		}
	}
	if serverHeader == "" && len(allHeaders) > 0 {
		serverHeader = allHeaders[0]
	}

	var title string
	titleRegex := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	titleMatches := titleRegex.FindStringSubmatch(bodyStr)
	if len(titleMatches) > 1 {
		title = SanitizeBanner(titleMatches[1])
		if len(title) > 100 {
			title = title[:97] + "..."
		}
		tLower := strings.ToLower(title)
		if strings.Contains(tLower, "jenkins") {
			addTech("jenkins")
		}
		if strings.Contains(tLower, "grafana") {
			addTech("grafana")
		}
		if strings.Contains(tLower, "gitlab") {
			addTech("gitlab")
		}
		if strings.Contains(tLower, "swagger") {
			addTech("swagger")
			addTech("api")
		}
		if strings.Contains(tLower, "spring") {
			addTech("springboot")
		}
	}

	bodyLower := strings.ToLower(bodyStr)

	// 1. Meta Generator regex
	metaGenRegex := regexp.MustCompile(`(?i)<meta\s+[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']`)
	for _, m := range metaGenRegex.FindAllStringSubmatch(bodyStr, -1) {
		if len(m) > 1 {
			genContent := strings.ToLower(m[1])
			if strings.Contains(genContent, "wordpress") {
				addTech("wordpress")
			}
			if strings.Contains(genContent, "drupal") {
				addTech("drupal")
			}
			if strings.Contains(genContent, "joomla") {
				addTech("joomla")
			}
			if strings.Contains(genContent, "sharepoint") {
				addTech("sharepoint")
			}
			if strings.Contains(genContent, "gatsby") {
				addTech("gatsby")
			}
			if strings.Contains(genContent, "hugo") {
				addTech("hugo")
			}
		}
	}

	// 2. HTML Body JS Objects & Scripts
	if strings.Contains(bodyStr, "__NEXT_DATA__") || strings.Contains(bodyStr, "/_next/static/") {
		addTech("nextjs")
	}
	if strings.Contains(bodyStr, "react-root") || strings.Contains(bodyStr, "data-reactroot") || strings.Contains(bodyStr, "_reactListening") {
		addTech("react")
	}
	if strings.Contains(bodyStr, "data-v-") || strings.Contains(bodyStr, "vue-router") || strings.Contains(bodyStr, "vuex") {
		addTech("vue")
	}
	if strings.Contains(bodyStr, "ng-app") || strings.Contains(bodyStr, "ng-controller") || strings.Contains(bodyStr, "ng-version") {
		addTech("angular")
	}
	if strings.Contains(bodyStr, "wp-content") || strings.Contains(bodyStr, "wp-includes") {
		addTech("wordpress")
	}
	if strings.Contains(bodyStr, "/sites/default/files") || strings.Contains(bodyStr, "drupal.js") {
		addTech("drupal")
	}
	if strings.Contains(bodyStr, "swagger-ui") || strings.Contains(bodyStr, "api-docs") {
		addTech("swagger")
		addTech("api")
	}
	if strings.Contains(bodyStr, "Whitelabel Error Page") || strings.Contains(bodyStr, "There was an unexpected error (type=") {
		addTech("springboot")
	}
	if strings.Contains(bodyLower, "django") || strings.Contains(bodyLower, "csrfmiddlewaretoken") {
		addTech("django")
	}
	if strings.Contains(bodyLower, "laravel_session") || strings.Contains(bodyLower, "x-csrf-token") {
		addTech("php")
	}
	if strings.Contains(bodyLower, "grafana-app") || strings.Contains(bodyLower, "window.grafanabootdata") {
		addTech("grafana")
	}
	if strings.Contains(bodyLower, "gon.default_avatar_url") || strings.Contains(bodyLower, "gl-avatar") || strings.Contains(bodyLower, "gitlab-") {
		addTech("gitlab")
	}
	if strings.Contains(bodyLower, "jenkins-head-icon") || strings.Contains(bodyLower, "jenkins_ver") || (strings.Contains(bodyLower, "<title>") && strings.Contains(bodyLower, "jenkins</title>")) {
		addTech("jenkins")
	}
	if strings.Contains(bodyLower, "kbn-name") || strings.Contains(bodyLower, "kibana") {
		addTech("elasticsearch")
	}

	// 3. WAF & CDN Detection
	var isWAF bool
	var wafName string
	allHeadersJoined := strings.ToLower(strings.Join(allHeaders, " "))

	if strings.Contains(allHeadersJoined, "akamaighost") || strings.Contains(allHeadersJoined, "akamai") || strings.Contains(bodyLower, "akamaighost") || strings.Contains(allHeadersJoined, "x-akamai") {
		isWAF = true
		wafName = "Akamai (AkamaiGHost)"
		addTech("waf-akamai")
	} else if strings.Contains(allHeadersJoined, "cloudflare") || strings.Contains(allHeadersJoined, "cf-ray") || strings.Contains(bodyLower, "cloudflare") {
		isWAF = true
		wafName = "Cloudflare"
		addTech("waf-cloudflare")
	} else if strings.Contains(allHeadersJoined, "cloudfront") || strings.Contains(allHeadersJoined, "awselb") || strings.Contains(allHeadersJoined, "x-amz-cf-id") {
		isWAF = true
		wafName = "AWS CloudFront / ELB"
		addTech("waf-aws")
	} else if strings.Contains(allHeadersJoined, "imperva") || strings.Contains(allHeadersJoined, "incap_ses") || strings.Contains(allHeadersJoined, "visid_incap") {
		isWAF = true
		wafName = "Imperva Incapsula"
		addTech("waf-imperva")
	} else if strings.Contains(allHeadersJoined, "f5") || strings.Contains(allHeadersJoined, "big-ip") {
		isWAF = true
		wafName = "F5 BIG-IP"
		addTech("waf-f5")
	} else if strings.Contains(allHeadersJoined, "sucuri") {
		isWAF = true
		wafName = "Sucuri WAF"
		addTech("waf-sucuri")
	}

	if isWAF {
		core.LogWarning("WAF / CDN Tespit Edildi (%s): %s:%d — Gerçek teknoloji WAF arkasında gizlenmiş olabilir.", wafName, ip, port)
		if resp.StatusCode == 400 || resp.StatusCode == 403 {
			title = fmt.Sprintf("WAF Protected (%s - Real Tech Hidden)", wafName)
		}
	}

	var detectedTechs []string
	for t := range detectedTechMap {
		detectedTechs = append(detectedTechs, t)
	}
	sort.Strings(detectedTechs)

	techs := append([]string{}, allHeaders...)
	for _, dt := range detectedTechs {
		techs = append(techs, dt)
	}

	fullServerCombined := strings.Join(allHeaders, " | ")
	if fullServerCombined == "" {
		fullServerCombined = "Unknown"
	}

	return HTTPProbeResult{
		IsHTTP:        true,
		Server:        SanitizeBanner(fullServerCombined),
		Title:         title,
		Technologies:  techs,
		DetectedTechs: detectedTechs,
		Banner:        SanitizeBanner(fmt.Sprintf("HTTP %d | Server: %s", resp.StatusCode, fullServerCombined)),
		WAFDetected:   isWAF,
		WAFName:       wafName,
	}
}

func isLikelyTLSPort(port int) bool {
	return port == 443 || port == 8443 || port == 9443 || port == 4443 || port == 10443 || port == 465 || port == 993 || port == 995
}

func shouldTryHTTP(port int, probeRes core.ProbeResult) bool {
	// If a non-HTTP service was already identified with high confidence, do NOT send HTTP probe
	if probeRes.ServiceName != "" && probeRes.ServiceName != "http" && probeRes.ServiceName != "https" && probeRes.Confidence >= 80 {
		return false
	}
	// Common HTTP ports
	httpPorts := map[int]bool{
		80: true, 443: true, 8080: true, 8443: true, 8000: true, 8888: true, 9000: true, 3000: true, 5000: true,
		8008: true, 8081: true, 8088: true, 7001: true, 7077: true, 9090: true, 9200: true, 9300: true, 50000: true,
		5985: true, 5986: true, 8444: true, 9443: true, 10443: true,
	}
	if httpPorts[port] {
		return true
	}
	// Check if banner contains HTTP keywords
	bUpper := strings.ToUpper(probeRes.Banner)
	if strings.Contains(bUpper, "HTTP/1.") || strings.Contains(bUpper, "HTTP/2") || strings.Contains(bUpper, "<HTML") || strings.Contains(bUpper, "SERVER:") || strings.Contains(bUpper, "LOCATION:") || strings.Contains(bUpper, "MICROSOFT-HTTPAPI") {
		return true
	}
	// If service is completely unknown, try HTTP as fallback
	if probeRes.ServiceName == "" {
		return true
	}
	return false
}

// AnalyzeService investigates a single port to identify full service details with high accuracy and confidence.
func AnalyzeService(portInfo core.PortInfo, timeout time.Duration) core.ServiceDetail {
	ip := portInfo.IP
	port := portInfo.Port
	hostname := portInfo.Hostname
	protocol := portInfo.Protocol
	if protocol == "" {
		protocol = "tcp"
	}

	// 1. Raw service probe & banner collection (Passive listen first, then minimal active probe)
	probeRes := GrabServiceBanner(ip, port, timeout)

	// 2. If raw probe produced a definite, high-confidence non-HTTP service, return immediately
	if probeRes.ServiceName != "" && probeRes.Confidence >= 80 && probeRes.ServiceName != "http" && probeRes.ServiceName != "https" {
		bannerRaw := SanitizeBanner(probeRes.Banner)
		if len(bannerRaw) > 255 {
			bannerRaw = bannerRaw[:252] + "..."
		}
		verSource := "raw_banner"
		if strings.Contains(probeRes.ProbeUsed, "binary") {
			verSource = "binary_parser"
		}
		return core.ServiceDetail{
			IP:                 ip,
			Hostname:           hostname,
			Port:               port,
			Protocol:           protocol,
			ServiceName:        probeRes.ServiceName,
			ServiceDescription: probeRes.ServiceDesc,
			ServiceVersion:     probeRes.Version,
			BannerRaw:          bannerRaw,
			VersionSource:      verSource,
			VersionConfidence:  probeRes.Confidence,
			ProbeUsed:          probeRes.ProbeUsed,
			Evidence:           probeRes.Evidence,
			SSLEnabled:         false,
			State:              "open",
		}
	}

	// 3. If port is likely TLS or service is not yet final, perform TLS probe
	isTLS := isLikelyTLSPort(port)
	if isTLS || probeRes.ServiceName == "" {
		sslInfo := ProbeTLSService(ip, port, timeout, hostname)
		if sslInfo != nil {
			probeRes.SSLInfo = sslInfo
			isTLS = true
			probeRes.Evidence = append(probeRes.Evidence, core.VersionEvidence{
				Source:     "tls_certificate",
				Detail:     fmt.Sprintf("Subject: %s | Issuer: %s", sslInfo.Subject, sslInfo.Issuer),
				Confidence: 35,
			})
			for _, h := range sslInfo.ObservedHints {
				probeRes.Evidence = append(probeRes.Evidence, core.VersionEvidence{
					Source:     "tls_hint",
					Detail:     h,
					Confidence: 40,
				})
			}
		}
	}

	// 4. If HTTP is plausible, execute HTTP Probe
	if shouldTryHTTP(port, probeRes) {
		httpRes := ProbeHTTPService(ip, port, isTLS, timeout, hostname)
		if !httpRes.IsHTTP && isTLS {
			// Also test plain HTTP on TLS port (e.g. misconfigured dev servers)
			httpRes = ProbeHTTPService(ip, port, false, 2*time.Second, hostname)
		}

		if httpRes.IsHTTP {
			svcName := "http"
			if isTLS {
				svcName = "https"
			}
			svcDesc := ""
			svcVer := ""
			verSource := "http_header"
			conf := 85

			if httpRes.Server != "" {
				sName, sDesc, sVer := ExtractVersionFromText(httpRes.Server)
				if sName != "" {
					svcDesc = sDesc
					svcVer = sVer
				}
			}

			if svcDesc == "" && len(httpRes.DetectedTechs) > 0 {
				svcDesc = strings.Title(httpRes.DetectedTechs[0])
			}
			if svcDesc == "" {
				svcDesc = "HTTP Web Service"
			}
			if httpRes.WAFDetected {
				svcDesc = fmt.Sprintf("Web Service (%s)", httpRes.WAFName)
			}

			bannerRaw := httpRes.Banner
			if probeRes.Banner != "" && !strings.Contains(bannerRaw, probeRes.Banner) {
				bannerRaw = bannerRaw + " | " + probeRes.Banner
			}
			bannerRaw = SanitizeBanner(bannerRaw)
			if len(bannerRaw) > 255 {
				bannerRaw = bannerRaw[:252] + "..."
			}

			var evidences []core.VersionEvidence
			evidences = append(evidences, probeRes.Evidence...)
			if httpRes.Server != "" {
				evidences = append(evidences, core.VersionEvidence{
					Source:     "http_server_header",
					Detail:     httpRes.Server,
					Confidence: 85,
				})
			}
			if httpRes.Title != "" {
				evidences = append(evidences, core.VersionEvidence{
					Source:     "http_title",
					Detail:     httpRes.Title,
					Confidence: 60,
				})
			}

			return core.ServiceDetail{
				IP:                 ip,
				Hostname:           hostname,
				Port:               port,
				Protocol:           protocol,
				ServiceName:        svcName,
				ServiceDescription: SanitizeBanner(svcDesc),
				ServiceVersion:     SanitizeBanner(svcVer),
				BannerRaw:          bannerRaw,
				HTTPTitle:          SanitizeBanner(httpRes.Title),
				HTTPServer:         SanitizeBanner(httpRes.Server),
				HTTPTechnologies:   httpRes.Technologies,
				DetectedTechs:      httpRes.DetectedTechs,
				VersionSource:      verSource,
				VersionConfidence:  conf,
				ProbeUsed:          "http_probe",
				Evidence:           evidences,
				SSLEnabled:         isTLS,
				SSLInfo:            probeRes.SSLInfo,
				WAFDetected:        httpRes.WAFDetected,
				WAFName:            httpRes.WAFName,
				State:              "open",
			}
		}
	}

	// 5. Fallback for raw / unknown / generic services
	serviceName := probeRes.ServiceName
	if serviceName == "" {
		serviceName = portInfo.ServiceName
	}
	if serviceName == "" {
		serviceName = "unknown"
	}
	serviceDesc := probeRes.ServiceDesc
	if serviceDesc == "" {
		serviceDesc = strings.ToUpper(serviceName) + " Service"
	}
	serviceVersion := probeRes.Version
	bannerRaw := SanitizeBanner(probeRes.Banner)
	if len(bannerRaw) > 255 {
		bannerRaw = bannerRaw[:252] + "..."
	}

	conf := probeRes.Confidence
	if conf == 0 {
		if serviceVersion != "" {
			conf = 70
		} else if serviceName != "unknown" {
			conf = 50
		} else {
			conf = 20
		}
	}

	return core.ServiceDetail{
		IP:                 ip,
		Port:               port,
		Protocol:           protocol,
		ServiceName:        SanitizeBanner(serviceName),
		ServiceDescription: SanitizeBanner(serviceDesc),
		ServiceVersion:     SanitizeBanner(serviceVersion),
		BannerRaw:          bannerRaw,
		VersionSource:      "raw_socket",
		VersionConfidence:  conf,
		ProbeUsed:          probeRes.ProbeUsed,
		Evidence:           probeRes.Evidence,
		SSLEnabled:         isTLS,
		SSLInfo:            probeRes.SSLInfo,
		State:              "open",
	}
}

// GrabBannersAndServices performs banner grabbing and version detection concurrently.
func GrabBannersAndServices(ports []core.PortInfo, concurrency int, timeout time.Duration, outputFile string) ([]core.ServiceDetail, error) {
	core.LogInfo("Banner Grabbing & Servis Tespiti başlatılıyor (%d açık port)...", len(ports))
	core.LogAudit("SERVICE_DETECTION_START", fmt.Sprintf("ports=%d", len(ports)), fmt.Sprintf("concurrency=%d", concurrency), "SUCCESS")

	if concurrency <= 0 {
		concurrency = 15
	}
	if concurrency > 15 {
		concurrency = 15
	}
	if timeout <= 0 {
		timeout = 4000 * time.Millisecond
	}

	portChan := make(chan core.PortInfo, len(ports))
	for _, p := range ports {
		portChan <- p
	}
	close(portChan)

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		services  []core.ServiceDetail
		hostLocks = make(map[string]*sync.Mutex)
		hostMu    sync.Mutex
	)

	getHostLock := func(ip string) *sync.Mutex {
		hostMu.Lock()
		defer hostMu.Unlock()
		if l, exists := hostLocks[ip]; exists {
			return l
		}
		l := &sync.Mutex{}
		hostLocks[ip] = l
		return l
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range portChan {
				hLock := getHostLock(p.IP)
				hLock.Lock()
				svc := AnalyzeService(p, timeout)
				time.Sleep(35 * time.Millisecond)
				hLock.Unlock()

				mu.Lock()
				services = append(services, svc)
				mu.Unlock()

				verStr := ""
				if svc.ServiceVersion != "" {
					verStr = " v" + svc.ServiceVersion
				}
				core.LogSuccess("Servis Tanımlandı: %s:%d -> %s%s (%s)", svc.IP, svc.Port, svc.ServiceName, verStr, svc.ServiceDescription)
			}
		}()
	}

	wg.Wait()

	sort.Slice(services, func(i, j int) bool {
		if services[i].IP == services[j].IP {
			return services[i].Port < services[j].Port
		}
		return services[i].IP < services[j].IP
	})

	if outputFile != "" {
		_ = core.SaveServices(services, outputFile)
		core.LogInfo("Servis Tespiti tamamlandı: %d servis kaydedildi (%s).", len(services), outputFile)
	} else {
		core.LogInfo("Servis Tespiti tamamlandı: %d servis tespit edildi.", len(services))
	}
	core.LogAudit("SERVICE_DETECTION_COMPLETE", "all", fmt.Sprintf("services=%d", len(services)), "SUCCESS")


	return services, nil
}

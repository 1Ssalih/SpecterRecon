package modules

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
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
}

var ServiceRegexRules = []ServiceRegexRule{
	// OpenSSH
	{
		Pattern:     regexp.MustCompile(`(?i)SSH-[\d\.]+-OpenSSH_([^\s]+)`),
		ServiceName: "ssh",
		Description: "OpenSSH",
		ExtractVer:  func(m []string) string { return m[1] },
	},
	{
		Pattern:     regexp.MustCompile(`(?i)SSH-[\d\.]+-([^\r\n]+)`),
		ServiceName: "ssh",
		Description: "SSH Server",
		ExtractVer:  func(m []string) string { return m[1] },
	},
	// HTTP Servers
	{
		Pattern:     regexp.MustCompile(`(?i)Apache/([\d\.]+)`),
		ServiceName: "http",
		Description: "Apache HTTP Server",
		ExtractVer:  func(m []string) string { return m[1] },
	},
	{
		Pattern:     regexp.MustCompile(`(?i)nginx/([\d\.]+)`),
		ServiceName: "http",
		Description: "nginx",
		ExtractVer:  func(m []string) string { return m[1] },
	},
	{
		Pattern:     regexp.MustCompile(`(?i)Microsoft-IIS/([\d\.]+)`),
		ServiceName: "http",
		Description: "Microsoft IIS",
		ExtractVer:  func(m []string) string { return m[1] },
	},
	{
		Pattern:     regexp.MustCompile(`(?i)lighttpd/([\d\.]+)`),
		ServiceName: "http",
		Description: "lighttpd",
		ExtractVer:  func(m []string) string { return m[1] },
	},
	{
		Pattern:     regexp.MustCompile(`(?i)Werkzeug/([\d\.]+)`),
		ServiceName: "http",
		Description: "Werkzeug (Python)",
		ExtractVer:  func(m []string) string { return m[1] },
	},
	{
		Pattern:     regexp.MustCompile(`(?i)PHP/([\d\.]+)`),
		ServiceName: "http",
		Description: "PHP",
		ExtractVer:  func(m []string) string { return m[1] },
	},
	{
		Pattern:     regexp.MustCompile(`(?i)Tomcat/([\d\.]+)`),
		ServiceName: "http",
		Description: "Apache Tomcat",
		ExtractVer:  func(m []string) string { return m[1] },
	},
	// FTP
	{
		Pattern:     regexp.MustCompile(`(?i)vsFTPd\s+([\d\.]+)`),
		ServiceName: "ftp",
		Description: "vsftpd",
		ExtractVer:  func(m []string) string { return m[1] },
	},
	{
		Pattern:     regexp.MustCompile(`(?i)ProFTPD\s+([\d\.]+)`),
		ServiceName: "ftp",
		Description: "ProFTPD",
		ExtractVer:  func(m []string) string { return m[1] },
	},
	{
		Pattern:     regexp.MustCompile(`(?i)220[- ].*FileZilla Server ([\d\.]+)`),
		ServiceName: "ftp",
		Description: "FileZilla Server",
		ExtractVer:  func(m []string) string { return m[1] },
	},
	// Databases
	{
		Pattern:     regexp.MustCompile(`(?i)([\d\.\-\w]+)-MariaDB`),
		ServiceName: "mysql",
		Description: "MariaDB",
		ExtractVer:  func(m []string) string { return m[1] },
	},
	{
		Pattern:     regexp.MustCompile(`(?i)redis_version:([\d\.]+)`),
		ServiceName: "redis",
		Description: "Redis",
		ExtractVer:  func(m []string) string { return m[1] },
	},
}

// SanitizeBanner removes non-printable, control, and invalid binary characters from banner strings.
func SanitizeBanner(s string) string {
	if s == "" {
		return ""
	}
	var sb strings.Builder
	for _, r := range s {
		// Keep printable characters, space, tab, newline, carriage return and valid printable unicode
		if (r >= 32 && r <= 126) || r == '\t' || r == '\n' || r == '\r' || (r > 127 && unicode.IsPrint(r)) {
			sb.WriteRune(r)
		} else if r == 0 || r < 32 || r == 127 || r == 0xFFFD {
			// Replace non-printable bytes with space
			sb.WriteByte(' ')
		}
	}
	// Normalize spaces
	cleaned := strings.Join(strings.Fields(sb.String()), " ")
	return strings.TrimSpace(cleaned)
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

// ExtractVersionFromText extracts service and version from banner text using regexes.
func ExtractVersionFromText(text string) (serviceName, description, version string) {
	sanitized := SanitizeBanner(text)
	for _, rule := range ServiceRegexRules {
		matches := rule.Pattern.FindStringSubmatch(sanitized)
		if len(matches) > 0 {
			ver := ""
			if rule.ExtractVer != nil {
				ver = rule.ExtractVer(matches)
			}
			return rule.ServiceName, rule.Description, SanitizeBanner(ver)
		}
	}
	return "", "", ""
}

// GrabRawSocketBanner connects to raw TCP socket and reads banner, handling binary protocols cleanly.
func GrabRawSocketBanner(ip string, port int, timeout time.Duration) (banner string, parsedSvc string, parsedDesc string, parsedVer string) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", "", "", ""
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
	reader := bufio.NewReader(conn)
	buf := make([]byte, 1024)
	n, _ := reader.Read(buf)

	if n > 0 {
		// Check for binary MySQL Handshake
		if port == 3306 || (n >= 5 && (buf[4] == 10 || buf[4] == 9)) {
			sName, sDesc, sVer, myBanner := ParseMySQLHandshake(buf[:n])
			if sName != "" {
				return myBanner, sName, sDesc, sVer
			}
		}
	}

	banner = SanitizeBanner(string(buf[:n]))

	if banner == "" {
		// Send probe
		probe := "\r\n\r\n"
		if port == 25 || port == 587 {
			probe = "EHLO recon.local\r\n"
		} else if port == 21 {
			probe = "SYST\r\n"
		} else if port == 6379 {
			probe = "INFO\r\n"
		}
		_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		_, _ = conn.Write([]byte(probe))
		_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
		n, _ = reader.Read(buf)
		if n > 0 {
			banner = SanitizeBanner(string(buf[:n]))
		}
	}

	return banner, "", "", ""
}

type HTTPProbeResult struct {
	IsHTTP       bool
	Server       string
	Title        string
	Technologies []string
	Banner       string
}

// ProbeHTTPService checks if service is HTTP/HTTPS and extracts headers and title.
func ProbeHTTPService(ip string, port int, isSSL bool, timeout time.Duration) HTTPProbeResult {
	proto := "http"
	if isSSL {
		proto = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", proto, ip, port)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: ip},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return HTTPProbeResult{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SpecterRecon/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return HTTPProbeResult{}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	bodyStr := string(bodyBytes)

	var allHeaders []string
	var serverHeader string
	for k, vList := range resp.Header {
		kLower := strings.ToLower(k)
		if kLower == "server" || kLower == "x-powered-by" || kLower == "via" {
			for _, v := range vList {
				cleanVal := SanitizeBanner(v)
				if cleanVal != "" {
					allHeaders = append(allHeaders, cleanVal)
					if kLower == "server" && serverHeader == "" {
						serverHeader = cleanVal
					}
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
	}

	var techs []string
	for _, h := range allHeaders {
		techs = append(techs, h)
	}
	bodyLower := strings.ToLower(bodyStr)
	if strings.Contains(bodyLower, "wp-content") || strings.Contains(bodyLower, "wordpress") {
		techs = append(techs, "WordPress")
	}
	if strings.Contains(bodyLower, "react") {
		techs = append(techs, "React")
	}

	fullServerCombined := strings.Join(allHeaders, " | ")
	if fullServerCombined == "" {
		fullServerCombined = "Unknown"
	}

	return HTTPProbeResult{
		IsHTTP:       true,
		Server:       SanitizeBanner(fullServerCombined),
		Title:        title,
		Technologies: techs,
		Banner:       SanitizeBanner(fmt.Sprintf("HTTP %d | Server: %s", resp.StatusCode, fullServerCombined)),
	}
}

// AnalyzeService investigates a single port to identify full service details.
func AnalyzeService(portInfo core.PortInfo, timeout time.Duration) core.ServiceDetail {
	ip := portInfo.IP
	port := portInfo.Port
	serviceName := portInfo.ServiceName
	if serviceName == "" {
		serviceName = "unknown"
	}

	isSSL := port == 443 || port == 8443 || port == 9443
	httpRes := ProbeHTTPService(ip, port, isSSL, timeout)
	if !httpRes.IsHTTP && !isSSL {
		// Test plain HTTP
		httpRes = ProbeHTTPService(ip, port, false, 2*time.Second)
	}

	var (
		serviceDesc    string
		serviceVersion string
		bannerRaw      string
		httpTitle      string
		httpServer     string
		httpTechs      []string
	)

	if httpRes.IsHTTP {
		if isSSL {
			serviceName = "https"
		} else {
			serviceName = "http"
		}
		httpTitle = httpRes.Title
		httpServer = httpRes.Server
		httpTechs = httpRes.Technologies
		bannerRaw = httpRes.Banner

		if httpServer != "" {
			sName, sDesc, sVer := ExtractVersionFromText(httpServer)
			if sName != "" {
				serviceDesc = sDesc
				serviceVersion = sVer
			}
		}
	}

	if serviceVersion == "" {
		rawBanner, parsedSvc, parsedDesc, parsedVer := GrabRawSocketBanner(ip, port, timeout)
		if parsedSvc != "" {
			serviceName = parsedSvc
			serviceDesc = parsedDesc
			serviceVersion = parsedVer
			bannerRaw = rawBanner
		} else if rawBanner != "" {
			if bannerRaw != "" {
				bannerRaw = bannerRaw + " | " + rawBanner
			} else {
				bannerRaw = rawBanner
			}
			sName, sDesc, sVer := ExtractVersionFromText(rawBanner)
			if sName != "" {
				serviceName = sName
				serviceDesc = sDesc
				serviceVersion = sVer
			}
		}
	}

	if serviceDesc == "" && serviceName != "" {
		serviceDesc = strings.ToUpper(serviceName) + " Service"
	}

	bannerRaw = SanitizeBanner(bannerRaw)
	if len(bannerRaw) > 255 {
		bannerRaw = bannerRaw[:252] + "..."
	}

	return core.ServiceDetail{
		IP:                 ip,
		Port:               port,
		Protocol:           portInfo.Protocol,
		ServiceName:        SanitizeBanner(serviceName),
		ServiceDescription: SanitizeBanner(serviceDesc),
		ServiceVersion:     SanitizeBanner(serviceVersion),
		BannerRaw:          bannerRaw,
		HTTPTitle:          SanitizeBanner(httpTitle),
		HTTPServer:         SanitizeBanner(httpServer),
		HTTPTechnologies:   httpTechs,
		SSLEnabled:         isSSL,
		State:              "open",
	}
}

// GrabBannersAndServices performs banner grabbing and version detection concurrently.
func GrabBannersAndServices(ports []core.PortInfo, concurrency int, timeout time.Duration, outputFile string) ([]core.ServiceDetail, error) {
	core.LogInfo("Banner Grabbing & Servis Tespiti başlatılıyor (%d açık port)...", len(ports))
	core.LogAudit("SERVICE_DETECTION_START", fmt.Sprintf("ports=%d", len(ports)), fmt.Sprintf("concurrency=%d", concurrency), "SUCCESS")

	if concurrency <= 0 {
		concurrency = 30
	}
	if timeout <= 0 {
		timeout = 3500 * time.Millisecond
	}

	portChan := make(chan core.PortInfo, len(ports))
	for _, p := range ports {
		portChan <- p
	}
	close(portChan)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		services []core.ServiceDetail
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range portChan {
				svc := AnalyzeService(p, timeout)
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
	}

	core.LogInfo("Servis Tespiti tamamlandı: %d servis kaydedildi (%s).", len(services), outputFile)
	core.LogAudit("SERVICE_DETECTION_COMPLETE", "all", fmt.Sprintf("services=%d", len(services)), "SUCCESS")

	return services, nil
}

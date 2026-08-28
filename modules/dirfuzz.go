package modules

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/wordlists"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)

var SensitiveKeywords = []string{".env", ".git", ".bak", "config", "backup", "sql", "id_rsa", "password", "secret", "private"}

type WordlistConfigFile struct {
	Quick map[string]string `yaml:"quick"`
	Full  map[string]string `yaml:"full"`
}

// LoadServiceWordlistMap loads the service-to-wordlist configuration map for the specified sizeMode ("quick" or "full").
// It seamlessly falls back to embedded YAML configuration if the external file is not present.
func LoadServiceWordlistMap(mapFile, sizeMode string) map[string]string {
	if mapFile == "" {
		mapFile = "wordlists/service_wordlist_map.yaml"
	}
	if sizeMode == "" {
		sizeMode = "quick"
	}

	result := make(map[string]string)
	data, err := os.ReadFile(mapFile)
	if err != nil {
		// Fallback to embedded YAML asset
		data = []byte(wordlists.ServiceWordlistMapYAML)
		err = nil
	}

	if err == nil {
		var cfg WordlistConfigFile
		if err := yaml.Unmarshal(data, &cfg); err == nil && (len(cfg.Quick) > 0 || len(cfg.Full) > 0) {
			if strings.ToLower(sizeMode) == "full" && len(cfg.Full) > 0 {
				for k, v := range cfg.Full {
					result[strings.ToLower(k)] = v
				}
			} else {
				for k, v := range cfg.Quick {
					result[strings.ToLower(k)] = v
				}
			}
		} else {
			// Flat map fallback
			var flatMap map[string]string
			if err := yaml.Unmarshal(data, &flatMap); err == nil && len(flatMap) > 0 {
				for k, v := range flatMap {
					result[strings.ToLower(k)] = v
				}
			}
		}
	}

	// Fallback defaults if YAML is missing or empty
	if len(result) == 0 {
		if strings.ToLower(sizeMode) == "full" {
			result = map[string]string{
				"jenkins":       "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Jenkins-Hudson.txt",
				"apache":        "wordlists/SecLists/Discovery/Web-Content/Web-Servers/Apache.txt",
				"iis":           "wordlists/SecLists/Discovery/Web-Content/Web-Servers/IIS.txt",
				"nginx":         "wordlists/SecLists/Discovery/Web-Content/Web-Servers/nginx.txt",
				"tomcat":        "wordlists/SecLists/Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt",
				"wordpress":     "wordlists/SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
				"drupal":        "wordlists/SecLists/Discovery/Web-Content/CMS/Drupal.txt",
				"joomla":        "wordlists/SecLists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt",
				"sharepoint":    "wordlists/SecLists/Discovery/Web-Content/CMS/Sharepoint-Ennumeration.txt",
				"springboot":    "wordlists/SecLists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt",
				"php":           "wordlists/SecLists/Discovery/Web-Content/Programming-Language-Specific/PHP.fuzz.txt",
				"aspnet":        "wordlists/SecLists/Discovery/Web-Content/Programming-Language-Specific/ASP.NET/CommonBackdoors-ASP.fuzz.txt",
				"gitlab":        "wordlists/SecLists/Discovery/Web-Content/Service-Specific/GitLab.txt",
				"grafana":       "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Grafana.txt",
				"elasticsearch": "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Elasticsearch-Kibana.txt",
				"swagger":       "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Swagger.txt",
				"api":           "wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt",
				"nextjs":        "wordlists/SecLists/Discovery/Web-Content/Frameworks/nextjs.txt",
				"django":        "wordlists/SecLists/Discovery/Web-Content/Frameworks/django.txt",
				"rails":         "wordlists/SecLists/Discovery/Web-Content/Frameworks/ruby-on-rails.txt",
				"default":       "wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt",
			}
		} else {
			result = map[string]string{
				"jenkins":       "wordlists/jenkins.txt",
				"apache":        "wordlists/apache.txt",
				"wordpress":     "wordlists/wordpress.txt",
				"iis":           "wordlists/SecLists/Discovery/Web-Content/Web-Servers/IIS.txt",
				"nginx":         "wordlists/SecLists/Discovery/Web-Content/Web-Servers/nginx.txt",
				"tomcat":        "wordlists/SecLists/Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt",
				"drupal":        "wordlists/SecLists/Discovery/Web-Content/CMS/Drupal.txt",
				"joomla":        "wordlists/SecLists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt",
				"sharepoint":    "wordlists/SecLists/Discovery/Web-Content/CMS/Sharepoint-Ennumeration.txt",
				"springboot":    "wordlists/SecLists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt",
				"php":           "wordlists/SecLists/Discovery/Web-Content/Programming-Language-Specific/PHP.fuzz.txt",
				"aspnet":        "wordlists/SecLists/Discovery/Web-Content/Programming-Language-Specific/ASP.NET/CommonBackdoors-ASP.fuzz.txt",
				"gitlab":        "wordlists/SecLists/Discovery/Web-Content/Service-Specific/GitLab.txt",
				"grafana":       "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Grafana.txt",
				"elasticsearch": "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Elasticsearch-Kibana.txt",
				"swagger":       "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Swagger.txt",
				"api":           "wordlists/api.txt",
				"nextjs":        "wordlists/nextjs.txt",
				"django":        "wordlists/django.txt",
				"rails":         "wordlists/rails.txt",
				"default":       "wordlists/common.txt",
			}
		}
	}

	return result
}

// MergeUnique combines multiple string slices into a single deduplicated slice, preserving order.
func MergeUnique(lists ...[]string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, list := range lists {
		for _, item := range list {
			trimmed := strings.TrimSpace(item)
			trimmed = strings.TrimPrefix(trimmed, "/")
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !seen[trimmed] {
				seen[trimmed] = true
				result = append(result, trimmed)
			}
		}
	}
	return result
}

// SelectWordlistForService selects the most relevant wordlist(s) for a detected HTTP service using a Tiered Priority System.
func SelectWordlistForService(svc core.ServiceDetail, wordlistMap map[string]string, defaultWordlist string) ([]string, string) {
	if defaultWordlist == "" {
		defaultWordlist = "wordlists/common.txt"
	}
	if wordlistMap == nil {
		wordlistMap = LoadServiceWordlistMap("", "quick")
	}

	haystack := strings.ToLower(fmt.Sprintf("%s %s %s %s %s %s %s",
		svc.ServiceName,
		svc.ServiceDescription,
		svc.HTTPTitle,
		svc.HTTPServer,
		strings.Join(svc.HTTPTechnologies, " "),
		strings.Join(svc.DetectedTechs, " "),
		svc.BannerRaw,
	))

	// Tiered Priority System:
	// Tier 1: High-Value Applications (CMS, CI/CD, DevOps Dashboards)
	// Tier 2: Frameworks & APIs (Spring Boot, Django, Rails, ASP.NET, PHP, Swagger, APIs, Next.js)
	// Tier 3: Dedicated Services (Elasticsearch, Kibana)
	// Tier 4: Underlying Web Servers / Infrastructure (Tomcat, IIS, Apache, Nginx, Lighttpd, Werkzeug)
	tiers := [][]string{
		{"jenkins", "gitlab", "grafana", "wordpress", "drupal", "joomla", "sharepoint"},
		{"springboot", "django", "rails", "aspnet", "php", "swagger", "api", "nextjs"},
		{"elasticsearch"},
		{"tomcat", "iis", "apache", "nginx", "lighttpd", "werkzeug"},
	}

	matchFoundInHaystack := func(key string) bool {
		switch key {
		case "springboot":
			return strings.Contains(haystack, "springboot") || strings.Contains(haystack, "spring-boot") || strings.Contains(haystack, "spring") || strings.Contains(haystack, "whitelabel error page") || strings.Contains(haystack, "x-application-context")
		case "aspnet":
			return strings.Contains(haystack, "asp.net") || strings.Contains(haystack, "aspnet") || strings.Contains(haystack, "__viewstate") || strings.Contains(haystack, "x-aspnet")
		case "iis":
			return strings.Contains(haystack, "iis") || strings.Contains(haystack, "microsoft-iis")
		case "nextjs":
			return strings.Contains(haystack, "nextjs") || strings.Contains(haystack, "next.js") || strings.Contains(haystack, "__next_data__") || strings.Contains(haystack, "/_next/")
		case "rails":
			return strings.Contains(haystack, "rails") || strings.Contains(haystack, "ruby on rails") || strings.Contains(haystack, "turbolinks")
		case "django":
			return strings.Contains(haystack, "django") || strings.Contains(haystack, "csrfmiddlewaretoken")
		case "swagger":
			return strings.Contains(haystack, "swagger") || strings.Contains(haystack, "openapi")
		case "api":
			return strings.Contains(haystack, "api") || strings.Contains(haystack, "rest") || strings.Contains(haystack, "graphql")
		default:
			return strings.Contains(haystack, key)
		}
	}

	isWordlistAvailable := func(p string) bool {
		if _, err := os.Stat(p); err == nil {
			return true
		}
		_, ok := wordlists.GetEmbeddedWordlist(p)
		return ok
	}

	var selectedLists []string
	var matchedKeys []string
	seenPaths := make(map[string]bool)

	for _, tier := range tiers {
		for _, key := range tier {
			if matchFoundInHaystack(key) {
				if path, ok := wordlistMap[key]; ok {
					if isWordlistAvailable(path) {
						if !seenPaths[path] {
							seenPaths[path] = true
							selectedLists = append(selectedLists, path)
							matchedKeys = append(matchedKeys, key)
						}
						break // Match found in this tier; continue scanning other tiers!
					} else {
						core.LogWarning("Wordlist bulunamadı: %s (kategori: %s)", path, key)
					}
				}
			}
		}
	}

	// Check any custom keys in wordlistMap not in predefined tiers
	for key, path := range wordlistMap {
		if key == "default" {
			continue
		}
		isPredefined := false
		for _, tier := range tiers {
			for _, tk := range tier {
				if tk == key {
					isPredefined = true
					break
				}
			}
			if isPredefined {
				break
			}
		}
		if !isPredefined && matchFoundInHaystack(key) {
			if isWordlistAvailable(path) {
				if !seenPaths[path] {
					seenPaths[path] = true
					selectedLists = append(selectedLists, path)
					matchedKeys = append(matchedKeys, key)
				}
			}
		}
	}

	if len(selectedLists) > 0 {
		return selectedLists, strings.Join(matchedKeys, "+")
	}

	if defPath, ok := wordlistMap["default"]; ok {
		if isWordlistAvailable(defPath) {
			return []string{defPath}, "default"
		}
	}

	return []string{defaultWordlist}, "common"
}

// GenerateTechnologyExtensionVariants expands base words with technology-specific file extensions based on detected web stack.
func GenerateTechnologyExtensionVariants(words []string, matchedTech string) []string {
	matchedTechLower := strings.ToLower(matchedTech)
	var extraVariants []string

	isIISorAspNet := strings.Contains(matchedTechLower, "iis") || strings.Contains(matchedTechLower, "aspnet") || strings.Contains(matchedTechLower, "microsoft")
	isPHP := strings.Contains(matchedTechLower, "php") || strings.Contains(matchedTechLower, "wordpress") || strings.Contains(matchedTechLower, "drupal") || strings.Contains(matchedTechLower, "joomla")
	isJava := strings.Contains(matchedTechLower, "tomcat") || strings.Contains(matchedTechLower, "springboot") || strings.Contains(matchedTechLower, "java")

	// High-interest root names for mutation
	targetRoots := []string{
		"index", "default", "login", "admin", "api", "auth", "portal", "dashboard",
		"test", "web", "config", "manage", "app", "service", "account", "user", "info",
	}

	if isIISorAspNet {
		aspExts := []string{".aspx", ".asp", ".axd", ".ashx", ".asmx", ".config"}
		for _, root := range targetRoots {
			for _, ext := range aspExts {
				extraVariants = append(extraVariants, root+ext)
			}
		}
		extraVariants = append(extraVariants, "web.config", "global.asax", "elmah.axd", "trace.axd", "appsettings.json")
	}

	if isPHP {
		phpExts := []string{".php", ".phtml", ".php.bak", ".inc"}
		for _, root := range targetRoots {
			for _, ext := range phpExts {
				extraVariants = append(extraVariants, root+ext)
			}
		}
		extraVariants = append(extraVariants, "config.php", "wp-config.php", "phpinfo.php", "database.php")
	}

	if isJava {
		javaPaths := []string{
			"actuator", "actuator/health", "actuator/env", "actuator/beans", "actuator/metrics",
			"swagger-ui.html", "v2/api-docs", "v3/api-docs", "manager/html", "host-manager/html",
		}
		extraVariants = append(extraVariants, javaPaths...)
	}

	return MergeUnique(words, extraVariants)
}

// AuditHTTPMethods sends an OPTIONS request to extract Allow / Public headers and highlight dangerous methods (TRACE, PUT, DELETE).
func AuditHTTPMethods(client *http.Client, baseURL string, targetHost string) []string {
	req, err := http.NewRequest("OPTIONS", baseURL, nil)
	if err != nil {
		return nil
	}
	if targetHost != "" {
		req.Host = targetHost
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SpecterRecon/0.8.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	allowHeader := resp.Header.Get("Allow")
	if allowHeader == "" {
		allowHeader = resp.Header.Get("Public")
	}

	if allowHeader == "" {
		return nil
	}

	var methods []string
	seen := make(map[string]bool)
	for _, m := range strings.Split(allowHeader, ",") {
		mClean := strings.ToUpper(strings.TrimSpace(m))
		if mClean != "" && !seen[mClean] {
			seen[mClean] = true
			methods = append(methods, mClean)
		}
	}

	if len(methods) > 0 {
		core.LogSuccess("HTTP Desteklenen Metotlar Keşfedildi (%s): [%s]", baseURL, strings.Join(methods, ", "))
		for _, m := range methods {
			if m == "TRACE" || m == "TRACK" {
				core.LogWarning("Güvensiz HTTP Metodu Aktif (%s): %s (XST - Cross-Site Tracing Riski)", baseURL, m)
			}
			if m == "PUT" || m == "DELETE" || m == "PROPFIND" {
				core.LogInfo("Yazma/Yönetim Metodu Aktif (%s): %s (WebDAV / Dosya Yönetimi)", baseURL, m)
			}
		}
	}

	return methods
}

// FetchRobotsTxtPaths requests /robots.txt and parses Disallow / Allow directives into candidate paths.
func FetchRobotsTxtPaths(client *http.Client, baseURL string, targetHost string) []string {
	robotsURL := fmt.Sprintf("%s/robots.txt", strings.TrimSuffix(baseURL, "/"))
	req, err := http.NewRequest("GET", robotsURL, nil)
	if err != nil {
		return nil
	}
	if targetHost != "" {
		req.Host = targetHost
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SpecterRecon/0.8.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	lines := strings.Split(string(bodyBytes), "\n")

	var discovered []string
	seen := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "disallow:") || strings.HasPrefix(strings.ToLower(line), "allow:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				path := strings.TrimSpace(parts[1])
				path = strings.TrimPrefix(path, "/")
				path = strings.Split(path, "?")[0] // Strip query params
				if path != "" && path != "*" && !seen[path] {
					seen[path] = true
					discovered = append(discovered, path)
				}
			}
		}
	}

	if len(discovered) > 0 {
		core.LogSuccess("robots.txt İçeriğinden %d Adet Gizli/Özel Yol Keşfedildi (%s)", len(discovered), baseURL)
	}

	return discovered
}

// LoadWordlist reads paths from wordlist file with embedded fallback.
func LoadWordlist(filepath string) []string {
	if filepath == "" {
		return nil
	}
	file, err := os.Open(filepath)
	if err == nil {
		defer file.Close()
		var words []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				words = append(words, strings.TrimPrefix(line, "/"))
			}
		}
		if len(words) > 0 {
			return words
		}
	}

	// Embedded memory fallback
	if embedded, ok := wordlists.GetEmbeddedWordlist(filepath); ok && len(embedded) > 0 {
		return embedded
	}

	core.LogWarning("Wordlist dosyası bulunamadı: %s", filepath)
	return nil
}

func isSensitivePath(path string) bool {
	pLower := strings.ToLower(path)
	for _, kw := range SensitiveKeywords {
		if strings.Contains(pLower, kw) {
			return true
		}
	}
	return false
}

// BaselineResponse holds characteristics of non-existent path responses for Catch-All / Wildcard detection.
type BaselineResponse struct {
	IsCatchAll       bool
	IsUnresponsive   bool
	StatusCode       int
	ContentLength    int64
	RedirectLocation string
	Title            string
}

func normalizeRedirectLocation(loc string) string {
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err == nil && u.Path != "" {
		return u.Path
	}
	if idx := strings.Index(loc, "?"); idx != -1 {
		return loc[:idx]
	}
	return loc
}

// DetectBaselineResponse probes 3 random non-existent paths to detect Wildcard / Catch-All redirection or soft 404 behavior.
func DetectBaselineResponse(client *http.Client, baseURL string, targetHost string) BaselineResponse {
	testPaths := []string{
		"specter-fp-check-x9y8z7-1234",
		"non-existent-probe-a1b2c3-5678",
		"random-garbage-check-m4n5o6-9012",
	}

	type probeResp struct {
		statusCode int
		length     int64
		location   string
		title      string
	}

	var results []probeResp

	for _, p := range testPaths {
		url := fmt.Sprintf("%s/%s", strings.TrimSuffix(baseURL, "/"), p)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		if targetHost != "" {
			req.Host = targetHost
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SpecterRecon/0.8.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		_ = resp.Body.Close()

		var title string
		re := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
		matches := re.FindStringSubmatch(string(bodyBytes))
		if len(matches) > 1 {
			title = strings.TrimSpace(matches[1])
		}

		results = append(results, probeResp{
			statusCode: resp.StatusCode,
			length:     int64(len(bodyBytes)),
			location:   resp.Header.Get("Location"),
			title:      title,
		})
	}

	if len(results) == 0 {
		return BaselineResponse{
			IsUnresponsive: true,
		}
	}

	if len(results) >= 2 {
		first := results[0]
		allMatch := true
		firstBaseLoc := normalizeRedirectLocation(first.location)

		for _, r := range results[1:] {
			if r.statusCode != first.statusCode {
				allMatch = false
				break
			}
			diff := r.length - first.length
			if diff < 0 {
				diff = -diff
			}
			rBaseLoc := normalizeRedirectLocation(r.location)
			// Tolerant size diff (45B) or matching redirect base path
			if diff > 45 && (firstBaseLoc == "" || firstBaseLoc != rBaseLoc) {
				allMatch = false
				break
			}
		}

		if allMatch && first.statusCode != 404 && first.statusCode != 405 {
			destHint := ""
			if firstBaseLoc != "" {
				destHint = fmt.Sprintf(" ➔ %s", firstBaseLoc)
			}
			core.LogWarning("Catch-All / Wildcard Yanıtı Tespit Edildi: Hedef bilinmeyen tüm yollara [%d] (~%dB%s) dönüyor. Sahte bulgular otomatik filtrelenecektir.",
				first.statusCode, first.length, destHint)
			return BaselineResponse{
				IsCatchAll:       true,
				StatusCode:       first.statusCode,
				ContentLength:    first.length,
				RedirectLocation: first.location,
				Title:            first.title,
			}
		}
	}

	return BaselineResponse{}
}

var (
	regexAWSAccessKey = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	regexGoogleAPIKey = regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)
	regexGitHubToken  = regexp.MustCompile(`\bghp_[0-9a-zA-Z]{36}\b`)
	regexSlackWebhook = regexp.MustCompile(`https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+`)
	regexJWT          = regexp.MustCompile(`\beyJ[a-zA-Z0-9\-_]{10,}\.eyJ[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]+\b`)
	regexPrivateKey   = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)
	regexDBConnString = regexp.MustCompile(`\b(?:postgres|mysql|mongodb|redis|amqp):\/\/[^:\s]+:[^@\s]+@[^\s]+\b`)
)

// ScanBodyForSecrets inspects HTTP response bodies for sensitive credentials, tokens, or private keys.
func ScanBodyForSecrets(body string) []string {
	var leaks []string
	if regexPrivateKey.MatchString(body) {
		leaks = append(leaks, "Private RSA/SSH Key")
	}
	if regexAWSAccessKey.MatchString(body) {
		leaks = append(leaks, "AWS Access Key")
	}
	if regexGoogleAPIKey.MatchString(body) {
		leaks = append(leaks, "Google API Key")
	}
	if regexGitHubToken.MatchString(body) {
		leaks = append(leaks, "GitHub PAT Token")
	}
	if regexSlackWebhook.MatchString(body) {
		leaks = append(leaks, "Slack Webhook URL")
	}
	if regexDBConnString.MatchString(body) {
		leaks = append(leaks, "Database Credentials")
	}
	if regexJWT.MatchString(body) {
		leaks = append(leaks, "JWT Token")
	}
	return leaks
}

// CheckDebugModeExposure detects framework debug stack traces and error pages.
func CheckDebugModeExposure(body string) string {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "whitelabel error page") && strings.Contains(lower, "timestamp") {
		return "Spring Boot Whitelabel (Debug Stack)"
	}
	if strings.Contains(lower, "django_settings_module") || (strings.Contains(lower, "traceback (most recent call last)") && strings.Contains(lower, "django")) {
		return "Django Debug Mode (Stack Trace)"
	}
	if strings.Contains(lower, "whoops! there was an error") || strings.Contains(lower, "ignition-app") {
		return "Laravel Ignition Debug (Whoops)"
	}
	if strings.Contains(lower, "fatal error:") && strings.Contains(lower, "stack trace:") {
		return "PHP Fatal Error / Stack Trace"
	}
	if strings.Contains(lower, "server error in '/' application") && strings.Contains(lower, "version information:") {
		return "ASP.NET Yellow Screen (Stack Trace)"
	}
	return ""
}

// FuzzSingleURL requests a single path and evaluates response with Catch-All baseline filter, secret leak scanning, and rate limiter support.
func FuzzSingleURL(client *http.Client, baseURL, path, matchTag string, statusFilter map[int]bool, limiter *rate.Limiter, baseline BaselineResponse, targetHost string, defaultMethods []string) *core.DirFuzzFinding {
	if limiter != nil {
		_ = limiter.Wait(context.Background())
	}

	url := fmt.Sprintf("%s/%s", strings.TrimSuffix(baseURL, "/"), path)
	start := time.Now()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	if targetHost != "" {
		req.Host = targetHost
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SpecterRecon/0.8.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 || resp.StatusCode == 503 {
		// Adaptive Rate-Limit Backoff
		time.Sleep(600 * time.Millisecond)
	}

	latency := float64(time.Since(start).Nanoseconds()) / 1e6

	if statusFilter[resp.StatusCode] {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		bodyStr := string(bodyBytes)
		contentLen := int64(len(bodyBytes))

		var title string
		if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			re := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
			matches := re.FindStringSubmatch(bodyStr)
			if len(matches) > 1 {
				title = strings.TrimSpace(matches[1])
				if len(title) > 60 {
					title = title[:57] + "..."
				}
			}
		}

		location := resp.Header.Get("Location")
		isSensitive := isSensitivePath(path)

		// Passive secret & credential leak scanning on response body
		leaks := ScanBodyForSecrets(bodyStr)
		debugMode := CheckDebugModeExposure(bodyStr)

		if len(leaks) > 0 {
			isSensitive = true
			leakTag := fmt.Sprintf("[SIZINTI: %s]", strings.Join(leaks, ", "))
			if title == "" {
				title = leakTag
			} else {
				title = title + " " + leakTag
			}
			core.LogWarning("🚨 HASSAS BİLGİ SIZINTISI (%s): %s ➔ %s", strings.Join(leaks, ", "), url, leakTag)
		}

		if debugMode != "" {
			isSensitive = true
			if title == "" {
				title = "[" + debugMode + "]"
			} else {
				title = title + " [" + debugMode + "]"
			}
			core.LogWarning("⚠️ DEBUG MODU / HATA SAYFASI AÇIK: %s ➔ %s", url, debugMode)
		}

		// 1. Catch-All Baseline Suppression
		if baseline.IsCatchAll && resp.StatusCode == baseline.StatusCode {
			diff := contentLen - baseline.ContentLength
			if diff < 0 {
				diff = -diff
			}
			baseLoc := normalizeRedirectLocation(location)
			baseBaselineLoc := normalizeRedirectLocation(baseline.RedirectLocation)

			// Suppress if size is within tolerance (45B) OR if redirect base path matches baseline redirect base path
			isRedirectMatch := (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 307 || resp.StatusCode == 308) &&
				baseBaselineLoc != "" && (baseLoc == baseBaselineLoc || strings.TrimRight(baseLoc, "/") == strings.TrimRight(baseBaselineLoc, "/"))

			if diff <= 45 || isRedirectMatch {
				// Only allow 200 OK responses through if they contain unique content or secret leaks
				if !(resp.StatusCode == 200 && (len(leaks) > 0 || (title != baseline.Title && title != ""))) {
					return nil
				}
			}
		}

		// Sensitive classification logic:
		// A path is only considered truly sensitive if it returns 200 OK (with content), OR
		// returns 401/403 on a target that does NOT return 401/403 as the global baseline.
		// Redirects (301/302) are NEVER marked as sensitive!
		if isSensitive {
			if resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 307 || resp.StatusCode == 308 {
				isSensitive = false
			} else if (resp.StatusCode == 401 || resp.StatusCode == 403) && baseline.IsCatchAll && baseline.StatusCode == resp.StatusCode {
				isSensitive = false
			}
		}

		// If sensitive keyword matched and status is 401 Unauthorized or 403 Forbidden
		if isSensitive && (resp.StatusCode == 401 || resp.StatusCode == 403) {
			if title == "" {
				title = "Potential Sensitive File (Access Denied)"
			} else {
				title = title + " [Access Denied]"
			}
		}

		// Extract allowed methods from response if provided by endpoint (e.g. 405 Method Not Allowed)
		var allowedMethods []string
		if allowHdr := resp.Header.Get("Allow"); allowHdr != "" {
			for _, m := range strings.Split(allowHdr, ",") {
				if mClean := strings.ToUpper(strings.TrimSpace(m)); mClean != "" {
					allowedMethods = append(allowedMethods, mClean)
				}
			}
		} else {
			allowedMethods = defaultMethods
		}

		return &core.DirFuzzFinding{
			URL:              url,
			Path:             "/" + path,
			StatusCode:       resp.StatusCode,
			ContentLength:    contentLen,
			RedirectLocation: location,
			Title:            title,
			ResponseTimeMs:   &latency,
			IsSensitive:      isSensitive,
			WordlistMatched:  matchTag,
			MatchedTech:      matchTag,
			AllowedMethods:   allowedMethods,
		}
	}

	return nil
}

// FuzzTargetService runs concurrent directory fuzzing against a single base URL with token bucket rate limiting.
func FuzzTargetService(baseURL string, wordlist []string, matchTag string, concurrency int, delayMs int) []core.DirFuzzFinding {
	return FuzzTargetServiceWithHost(baseURL, "", wordlist, matchTag, concurrency, delayMs)
}

// FuzzTargetServiceWithHost runs directory fuzzing with explicit Host header, HTTP methods audit, and baseline Catch-All suppression.
func FuzzTargetServiceWithHost(baseURL string, targetHost string, wordlist []string, matchTag string, concurrency int, delayMs int) []core.DirFuzzFinding {
	if concurrency <= 0 {
		concurrency = 25
	}

	// Global Token Bucket Rate Limiter
	var limiter *rate.Limiter
	if delayMs > 0 {
		r := rate.Limit(1000.0 / float64(delayMs))
		limiter = rate.NewLimiter(r, 1)
	}

	statusFilter := map[int]bool{
		200: true, 204: true, 301: true, 302: true, 303: true, 307: true, 308: true, 401: true, 403: true, 405: true, 500: true,
	}

	sniHost := targetHost
	if sniHost == "" {
		if u, err := url.Parse(baseURL); err == nil {
			sniHost = u.Hostname()
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         sniHost,
			MinVersion:         tls.VersionTLS10,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   4 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. Audit HTTP Methods on root URL (OPTIONS request)
	rootAllowedMethods := AuditHTTPMethods(client, baseURL, targetHost)

	// 2. Fetch robots.txt and harvest crawler-excluded internal paths
	robotsPaths := FetchRobotsTxtPaths(client, baseURL, targetHost)

	// 3. Dynamic extension expansion based on technology
	enrichedWordlist := GenerateTechnologyExtensionVariants(wordlist, matchTag)
	if len(robotsPaths) > 0 {
		enrichedWordlist = MergeUnique(robotsPaths, enrichedWordlist)
	}

	totalWords := len(enrichedWordlist)
	core.LogInfo("Dizin Taraması başlatılıyor: Hedef='%s', Liste='%s', Kelime Sayısı=%d", baseURL, matchTag, totalWords)
	core.LogAudit("DIR_FUZZ_START", baseURL, fmt.Sprintf("words=%d, matchTag=%s, concurrency=%d, host=%s", totalWords, matchTag, concurrency, targetHost), "SUCCESS")

	// 4. Baseline Catch-All Probing
	baseline := DetectBaselineResponse(client, baseURL, targetHost)
	if baseline.IsUnresponsive {
		core.LogWarning("Hedef web servisi ('%s') HTTP isteklerine yanıt vermiyor. Dizin fuzzing adımı atlandı.", baseURL)
		return nil
	}

	wordChan := make(chan string, totalWords)
	for _, w := range enrichedWordlist {
		wordChan <- w
	}
	close(wordChan)

	var (
		wg               sync.WaitGroup
		mu               sync.Mutex
		findings         []core.DirFuzzFinding
		processedCount   int64
		startTime        = time.Now()
		sizeFrequencyMap = make(map[string]int)
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range wordChan {
				res := FuzzSingleURL(client, baseURL, w, matchTag, statusFilter, limiter, baseline, targetHost, rootAllowedMethods)
				curr := atomic.AddInt64(&processedCount, 1)

				if res != nil {
					// Dynamic soft-404 / wildcard clustering filter:
					// Bucketize response size into 35-byte intervals
					sizeBucket := (res.ContentLength / 35) * 35
					freqKey := fmt.Sprintf("%d:%d", res.StatusCode, sizeBucket)
					mu.Lock()
					sizeFrequencyMap[freqKey]++
					count := sizeFrequencyMap[freqKey]
					mu.Unlock()

					// If any non-200 status (e.g. 302, 401, 403, 500) repeats more than 6 times with similar size:
					if res.StatusCode != 200 && count > 6 {
						continue // Suppress repetitive wildcard / catch-all flood
					}

					mu.Lock()
					findings = append(findings, *res)
					mu.Unlock()

					tag := ""
					if res.IsSensitive && res.StatusCode == 200 {
						tag = " [KRİTİK DOSYA]"
					} else if res.IsSensitive && (res.StatusCode == 401 || res.StatusCode == 403) {
						tag = " [KRİTİK DOSYA - ERİŞİM ENGELLENDİ]"
					}
					core.LogSuccess("Dizin Bulundu: [%d] %s (Boyut: %dB)%s", res.StatusCode, res.URL, res.ContentLength, tag)
				}

				// Periodic progress log for large wordlists
				if totalWords >= 2000 {
					step := int64(totalWords / 5)
					if step > 5000 {
						step = 5000
					}
					if step > 0 && curr%step == 0 {
						elapsed := time.Since(startTime).Seconds()
						if elapsed > 0 {
							rps := float64(curr) / elapsed
							pct := float64(curr) / float64(totalWords) * 100
							mu.Lock()
							foundCount := len(findings)
							mu.Unlock()
							core.LogInfo("Fuzzing İlerlemesi (%s): %d/%d (%%%.1f) | Hız: %.0f req/s | Bulgu: %d",
								matchTag, curr, totalWords, pct, rps, foundCount)
						}
					}
				}
			}
		}()
	}

	wg.Wait()

	// 5. Recursive Fuzzing on Discovered High-Value Directories (e.g. /admin/, /api/, /v1/, /portal/, /app/, /backup/)
	highValueDirNames := map[string]bool{
		"admin": true, "api": true, "v1": true, "v2": true, "portal": true, "dev": true,
		"app": true, "backup": true, "manage": true, "dashboard": true, "internal": true,
		"private": true, "secure": true, "panel": true, "auth": true, "ws": true, "rest": true,
	}

	var recursiveDirs []string
	seenRecDirs := make(map[string]bool)
	for _, f := range findings {
		cleanPath := strings.ToLower(strings.Trim(f.Path, "/"))
		// Only recurse on top-level discovered directories without extensions
		if cleanPath != "" && !strings.Contains(cleanPath, "/") && !strings.Contains(cleanPath, ".") {
			isDirRedirect := (f.StatusCode == 301 || f.StatusCode == 302) && strings.HasSuffix(f.RedirectLocation, "/")
			if highValueDirNames[cleanPath] || isDirRedirect {
				if !seenRecDirs[cleanPath] {
					seenRecDirs[cleanPath] = true
					recursiveDirs = append(recursiveDirs, cleanPath)
				}
			}
		}
	}

	if len(recursiveDirs) > 0 {
		if len(recursiveDirs) > 5 {
			recursiveDirs = recursiveDirs[:5]
		}
		recursiveWords := []string{
			"login", "users", "admin", "config", "settings", "keys", "backup", "db", "sql",
			"logs", "test", "v1", "v2", "swagger.json", "openapi.json", "env", "health", "status",
			"export", "import", "upload", "download", "profile", "auth", "token", "session",
		}
		core.LogInfo("Özyinelemeli (Recursive) Dizin Keşfi: %d kök dizin derinleştiriliyor (%s)...",
			len(recursiveDirs), strings.Join(recursiveDirs, ", "))

		for _, rDir := range recursiveDirs {
			for _, rWord := range recursiveWords {
				subPath := rDir + "/" + rWord
				if res := FuzzSingleURL(client, baseURL, subPath, matchTag, statusFilter, limiter, baseline, targetHost, rootAllowedMethods); res != nil {
					findings = append(findings, *res)
					tag := ""
					if res.IsSensitive {
						tag = " [KRİTİK DOSYA]"
					}
					core.LogSuccess("Özyinelemeli Dizin Bulundu: [%d] %s (Boyut: %dB)%s", res.StatusCode, res.URL, res.ContentLength, tag)
				}
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Path < findings[j].Path
	})

	return findings
}

// RunDirFuzzing orchestrates directory fuzzing across all open HTTP/HTTPS services with smart multi-list unioning.
func RunDirFuzzing(services []core.ServiceDetail, wordlistSizeMode string, defaultWordlist, sensitivePath string, concurrency int, delayMs int, outputJSON, outputTxt string) ([]core.DirFuzzFinding, error) {
	if wordlistSizeMode == "" {
		wordlistSizeMode = "quick"
	}
	if defaultWordlist == "" {
		if wordlistSizeMode == "full" {
			defaultWordlist = "wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
		} else {
			defaultWordlist = "wordlists/common.txt"
		}
	}
	if sensitivePath == "" {
		sensitivePath = "wordlists/sensitive.txt"
	}

	wordlistMap := LoadServiceWordlistMap("", wordlistSizeMode)
	sensitiveWords := LoadWordlist(sensitivePath)

	var httpServices []core.ServiceDetail
	for _, s := range services {
		sName := strings.ToLower(s.ServiceName)
		if strings.Contains(sName, "http") || s.Port == 80 || s.Port == 443 || s.Port == 8080 || s.Port == 8443 || s.Port == 3000 || s.Port == 5000 {
			httpServices = append(httpServices, s)
		}
	}

	if len(httpServices) == 0 {
		core.LogInfo("Dizin taraması için açık HTTP/HTTPS servisi tespit edilmedi.")
		_ = core.SaveFindings(nil, outputJSON, outputTxt)
		return nil, nil
	}

	core.LogInfo("Toplam %d HTTP/HTTPS servisi taranacak (Wordlist Modu: %s).", len(httpServices), strings.ToUpper(wordlistSizeMode))
	var allFindings []core.DirFuzzFinding

	for _, svc := range httpServices {
		proto := "http"
		if svc.SSLEnabled || svc.Port == 443 || svc.Port == 8443 {
			proto = "https"
		}
		baseURL := fmt.Sprintf("%s://%s:%d", proto, svc.IP, svc.Port)

		// Smart multi-list wordlist selection
		selectedWordlistPaths, matchKey := SelectWordlistForService(svc, wordlistMap, defaultWordlist)

		var wordlistsToMerge [][]string
		wordlistsToMerge = append(wordlistsToMerge, sensitiveWords)

		isCriticalPort := svc.Port == 80 || svc.Port == 443 || svc.Port == 8080 || svc.Port == 8443
		if len(selectedWordlistPaths) > 1 && (wordlistSizeMode == "full" || isCriticalPort) {
			// Multi-List Union: merge top 2 matched technologies
			for i := 0; i < len(selectedWordlistPaths) && i < 2; i++ {
				wordlistsToMerge = append(wordlistsToMerge, LoadWordlist(selectedWordlistPaths[i]))
			}
			if wordlistSizeMode == "full" {
				wordlistsToMerge = append(wordlistsToMerge, LoadWordlist(defaultWordlist))
			}
		} else if len(selectedWordlistPaths) > 0 {
			wordlistsToMerge = append(wordlistsToMerge, LoadWordlist(selectedWordlistPaths[0]))
		} else {
			wordlistsToMerge = append(wordlistsToMerge, LoadWordlist(defaultWordlist))
		}

		combined := MergeUnique(wordlistsToMerge...)

		displayNames := make([]string, len(selectedWordlistPaths))
		for idx, p := range selectedWordlistPaths {
			displayNames[idx] = filepath.Base(p)
		}
		core.LogInfo("Servis '%s:%d' için wordlist seçildi: %s (%s, toplam %d kelime)", svc.IP, svc.Port, strings.Join(displayNames, "+"), matchKey, len(combined))

		found := FuzzTargetServiceWithHost(baseURL, svc.Hostname, combined, matchKey, concurrency, delayMs)
		allFindings = append(allFindings, found...)
	}

	if outputJSON != "" || outputTxt != "" {
		_ = core.SaveFindings(allFindings, outputJSON, outputTxt)
	}

	core.LogInfo("Dizin Taraması tamamlandı: %d bulgu kaydedildi (%s & %s).", len(allFindings), outputJSON, outputTxt)
	core.LogAudit("DIR_FUZZ_COMPLETE", "all", fmt.Sprintf("total_findings=%d", len(allFindings)), "SUCCESS")

	return allFindings, nil
}

package modules

import (
	"bufio"
	"context"
	"crypto/md5"
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
	// Tier 1: High-Value Applications (Exchange, CMS, CI/CD, DevOps Dashboards)
	// Tier 2: Frameworks & APIs (Spring Boot, Django, Rails, ASP.NET, PHP, Swagger, APIs, Next.js)
	// Tier 3: Dedicated Services (Elasticsearch, Kibana)
	// Tier 4: Underlying Web Servers / Infrastructure (Tomcat, IIS, Apache, Nginx, Lighttpd, Werkzeug)
	tiers := [][]string{
		{"exchange", "jenkins", "gitlab", "grafana", "wordpress", "drupal", "joomla", "sharepoint"},
		{"springboot", "django", "rails", "aspnet", "php", "swagger", "api", "nextjs"},
		{"elasticsearch"},
		{"tomcat", "iis", "apache", "nginx", "lighttpd", "werkzeug"},
	}

	matchFoundInHaystack := func(key string) bool {
		switch key {
		case "exchange":
			return strings.Contains(haystack, "exchange") || strings.Contains(haystack, "owa") || strings.Contains(haystack, "outlook web") || strings.Contains(haystack, "autodiscover")
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
	isExchange := strings.Contains(matchedTechLower, "exchange")

	targetRoots := []string{
		"index", "default", "login", "admin", "api", "auth", "portal", "dashboard",
		"test", "web", "config", "manage", "app", "service", "account", "user", "info",
	}

	if isIISorAspNet {
		// Mevcut uzantılar
		aspExts := []string{".aspx", ".asp", ".axd", ".ashx", ".asmx", ".config"}
		for _, root := range targetRoots {
			for _, ext := range aspExts {
				extraVariants = append(extraVariants, root+ext)
			}
		}

		// ============================================================
		// YENİ: IIS Critical Paths — Hassas ve yüksek değerli endpoint'ler
		// ============================================================

		// 1. ASP.NET Debug/Tracing Handlers
		iisDebugPaths := []string{
			"elmah.axd",
			"trace.axd",
			"WebResource.axd",
			"ScriptResource.axd",
			"eWebEditor.axd",
			"Telerik.Web.UI.WebResource.axd",
			"Telerik.Web.UI.DialogHandler.aspx",
			"Telerik.Web.UI.SpellCheckHandler.axd",
		}
		extraVariants = append(extraVariants, iisDebugPaths...)

		// 2. Configuration Files
		iisConfigPaths := []string{
			"web.config",
			"web.config.bak",
			"web.config.old",
			"web.config.save",
			"web.config~",
			"web.config.txt",
			"web.config.xml",
			"web.config.swp",
			"machine.config",
			"Global.asax",
			"Global.asax.cs",
			"Global.asax.vb",
			"appsettings.json",
			"appsettings.Development.json",
			"appsettings.Production.json",
			"packages.config",
			"nuget.config",
			"web.Debug.config",
			"web.Release.config",
		}
		extraVariants = append(extraVariants, iisConfigPaths...)

		// 3. SharePoint Paths (often co-hosted on IIS)
		sharePointPaths := []string{
			"_layouts/",
			"_layouts/15/",
			"_layouts/15/settings.aspx",
			"_layouts/15/viewlsts.aspx",
			"_vti_bin/",
			"_vti_bin/shtml.dll",
			"_vti_bin/_vti_adm/admin.dll",
			"_vti_bin/_vti_aut/author.dll",
			"_vti_inf.html",
			"_catalogs/",
			"_catalogs/masterpage/",
			"_catalogs/wp/",
			"_catalogs/wt/",
			"SitePages/",
			"SiteAssets/",
			"Style Library/",
		}
		extraVariants = append(extraVariants, sharePointPaths...)

		// 4. ASP.NET MVC/API Endpoints
		iisAPIPaths := []string{
			"api/",
			"api/values",
			"api/health",
			"api/status",
			"api/v1/",
			"api/v2/",
			"swagger/",
			"swagger/ui/",
			"swagger/v1/swagger.json",
			"swagger/v2/swagger.json",
			"help/",
			"help/api/",
			"signalr/hubs",
			"odata/",
			"hangfire/",
			"Elmah",
			"elmah",
		}
		extraVariants = append(extraVariants, iisAPIPaths...)

		// 5. IIS Default/Management Files
		iisDefaultPaths := []string{
			"iisstart.htm",
			"iis-85.png",
			"iisstart.png",
			"aspnet_client/",
			"aspnet_client/system_web/",
			"aspnet_client/system_web/4_0_30319/",
		}
		extraVariants = append(extraVariants, iisDefaultPaths...)

		// 6. IIS Virtual Directories (common)
		iisVirtualDirs := []string{
			"certsrv/",
			"certenroll/",
			"Rpc/",
			"RpcProxy/",
			"MSADC/",
			"IISADMPWD/",
			"scripts/",
			"_vti_pvt/",
			"_private/",
			"fpdb/",
			"_fpclass/",
		}
		extraVariants = append(extraVariants, iisVirtualDirs...)

		// 7. Backup & Source Disclosure
		iisBackupPaths := []string{
			"web.config.bak",
			"web.config.old",
			"web.config.orig",
			"web.config.save",
			"web.config.txt",
			"web.config~",
			"Default.aspx.cs",
			"Default.aspx.vb",
			"Default.aspx.designer.cs",
			"bin/",
			"App_Data/",
			"App_Code/",
			"Logs/",
			"logs/",
			"ErrorPages/",
			"Errors/",
		}
		extraVariants = append(extraVariants, iisBackupPaths...)

		// 8. Telerik Vulnerability Paths (CVE-2017-9248, CVE-2019-18935)
		telerikPaths := []string{
			"Telerik.Web.UI.WebResource.axd?type=rau",
			"Telerik.Web.UI.DialogHandler.aspx",
			"Telerik.Web.UI.SpellCheckHandler.axd",
			"Telerik.Web.UI.ChartImage.axd",
		}
		extraVariants = append(extraVariants, telerikPaths...)
	}

	if isPHP {
		phpExts := []string{".php", ".phtml", ".php.bak", ".php~", ".php.old", ".inc", ".phps", ".php5", ".php7"}
		for _, root := range targetRoots {
			for _, ext := range phpExts {
				extraVariants = append(extraVariants, root+ext)
			}
		}
		extraVariants = append(extraVariants,
			"config.php", "wp-config.php", "phpinfo.php", "database.php",
			"configuration.php", "settings.php", "db.php", "conn.php",
			"connect.php", "include.php", "functions.php", "init.php",
			".env", ".htaccess", ".htpasswd", "composer.json", "composer.lock",
			"vendor/", "vendor/autoload.php",
		)
	}

	if isJava {
		javaPaths := []string{
			"actuator", "actuator/", "actuator/health", "actuator/env", "actuator/beans",
			"actuator/metrics", "actuator/conditions", "actuator/configprops",
			"actuator/mappings", "actuator/info", "actuator/loggers",
			"actuator/threaddump", "actuator/httptrace", "actuator/heapdump",
			"actuator/jolokia", "actuator/auditevents", "actuator/flyway",
			"actuator/liquibase", "actuator/prometheus", "actuator/scheduledtasks",
			"actuator/sessions", "actuator/shutdown",
			"swagger-ui.html", "swagger-ui/", "v2/api-docs", "v3/api-docs",
			"swagger-resources", "webjars/",
			"manager/html", "manager/status", "host-manager/html",
			"jmx-console/", "web-console/", "invoker/JMXInvokerServlet",
			"h2-console/", "console/", "debug/",
		}
		extraVariants = append(extraVariants, javaPaths...)
	}

	if isExchange {
		exchangeExtra := []string{
			"owa/auth/logon.aspx",
			"owa/auth/logoff.aspx",
			"EWS/Exchange.asmx",
			"Autodiscover/Autodiscover.xml",
			"ecp/default.aspx",
			"Microsoft-Server-ActiveSync",
			"PowerShell",
			"OAB",
			"mapi/emsmdb/",
		}
		extraVariants = append(extraVariants, exchangeExtra...)
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

// BaselineSignature captures characteristics of a non-existent path response.
type BaselineSignature struct {
	StatusCode       int
	ContentLength    int64
	RedirectLocation string
	Title            string
	BodySnippetHash  uint32
	BodyHash         string
}

// BaselineResponse holds characteristics of non-existent path responses for Catch-All / Wildcard detection.
type BaselineResponse struct {
	IsCatchAll       bool
	IsUnresponsive   bool
	Signatures       []BaselineSignature
	StatusCode       int
	ContentLength    int64
	RedirectLocation string
	Title            string
	BodySnippetHash  uint32
	BodyHash         string
}

func computeMD5Hash(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	h := md5.Sum(body)
	return fmt.Sprintf("%x", h)
}

func computeBodySnippetHash(body []byte) uint32 {
	if len(body) == 0 {
		return 0
	}
	limit := 128
	if len(body) < limit {
		limit = len(body)
	}
	var h uint32 = 2166136261
	for _, b := range body[:limit] {
		h ^= uint32(b)
		h *= 16777619
	}
	return h
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

// DetectBaselineResponse probes diverse non-existent paths to detect Wildcard / Catch-All redirection or soft 404 behavior.
func DetectBaselineResponse(client *http.Client, baseURL string, targetHost string) BaselineResponse {
	testPaths := []string{
		"specter-fp-check-x9y8z7-1234",
		"non-existent-probe-a1b2c3.html",
		"random-garbage-check-m4n5o6.aspx",
		"test-non-exist-dir/probe.php",
		"wildcard-check-7f8e9d-sub/index",
	}

	type probeResp struct {
		statusCode int
		length     int64
		location   string
		title      string
		bodyHash   string
		snippetH   uint32
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
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SpecterRecon/0.9.0")

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
			bodyHash:   computeMD5Hash(bodyBytes),
			snippetH:   computeBodySnippetHash(bodyBytes),
		})
	}

	if len(results) == 0 {
		return BaselineResponse{
			IsUnresponsive: true,
		}
	}

	// Cluster probe responses by status code and signature
	type sigCluster struct {
		status   int
		lengths  []int64
		location string
		title    string
		bodyHash string
		snippetH uint32
		count    int
	}

	var clusters []sigCluster
	for _, r := range results {
		matched := false
		rBaseLoc := normalizeRedirectLocation(r.location)

		for i := range clusters {
			if clusters[i].status == r.statusCode {
				cBaseLoc := normalizeRedirectLocation(clusters[i].location)
				diff := r.length - clusters[i].lengths[0]
				if diff < 0 {
					diff = -diff
				}

				isRedirectMatch := (r.statusCode >= 300 && r.statusCode < 400) &&
					(cBaseLoc == rBaseLoc || (cBaseLoc != "" && rBaseLoc != "" && strings.TrimRight(cBaseLoc, "/") == strings.TrimRight(rBaseLoc, "/")))

				isBodyMatch := (clusters[i].bodyHash != "" && clusters[i].bodyHash == r.bodyHash) || diff <= 50 || (clusters[i].snippetH != 0 && clusters[i].snippetH == r.snippetH) || (clusters[i].title != "" && clusters[i].title == r.title)

				if isRedirectMatch || isBodyMatch {
					clusters[i].lengths = append(clusters[i].lengths, r.length)
					clusters[i].count++
					matched = true
					break
				}
			}
		}

		if !matched {
			clusters = append(clusters, sigCluster{
				status:   r.statusCode,
				lengths:  []int64{r.length},
				location: r.location,
				title:    r.title,
				bodyHash: r.bodyHash,
				snippetH: r.snippetH,
				count:    1,
			})
		}
	}

	var detectedSigs []BaselineSignature
	for _, c := range clusters {
		// If at least 2 probe responses share the same signature and status is not standard 404/405
		if c.count >= 2 && c.status != 404 && c.status != 405 {
			var totalLen int64
			for _, l := range c.lengths {
				totalLen += l
			}
			avgLen := totalLen / int64(len(c.lengths))

			sig := BaselineSignature{
				StatusCode:       c.status,
				ContentLength:    avgLen,
				RedirectLocation: c.location,
				Title:            c.title,
				BodySnippetHash:  c.snippetH,
				BodyHash:         c.bodyHash,
			}
			detectedSigs = append(detectedSigs, sig)

			destHint := ""
			baseLoc := normalizeRedirectLocation(c.location)
			if baseLoc != "" {
				destHint = fmt.Sprintf(" ➔ %s", baseLoc)
			}
			core.LogWarning("Catch-All / Wildcard Yanıtı Tespit Edildi: Hedef bilinmeyen tüm yollara [%d] (~%dB%s, hash: %s) dönüyor. Sahte bulgular otomatik filtrelenecektir.",
				c.status, avgLen, destHint, c.bodyHash)
		}
	}

	if len(detectedSigs) > 0 {
		primary := detectedSigs[0]
		return BaselineResponse{
			IsCatchAll:       true,
			Signatures:       detectedSigs,
			StatusCode:       primary.StatusCode,
			ContentLength:    primary.ContentLength,
			RedirectLocation: primary.RedirectLocation,
			Title:            primary.Title,
			BodySnippetHash:  primary.BodySnippetHash,
			BodyHash:         primary.BodyHash,
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
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SpecterRecon/0.9.0")

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
		bodyHash := computeBodySnippetHash(bodyBytes)
		bHash := computeMD5Hash(bodyBytes)

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

		// 1. Multi-Signature Catch-All Baseline Suppression
		if baseline.IsCatchAll {
			sigsToCheck := baseline.Signatures
			if len(sigsToCheck) == 0 {
				sigsToCheck = []BaselineSignature{{
					StatusCode:       baseline.StatusCode,
					ContentLength:    baseline.ContentLength,
					RedirectLocation: baseline.RedirectLocation,
					Title:            baseline.Title,
					BodySnippetHash:  baseline.BodySnippetHash,
					BodyHash:         baseline.BodyHash,
				}}
			}

			baseLoc := normalizeRedirectLocation(location)
			for _, sig := range sigsToCheck {
				if resp.StatusCode == sig.StatusCode {
					diff := contentLen - sig.ContentLength
					if diff < 0 {
						diff = -diff
					}
					sigBaseLoc := normalizeRedirectLocation(sig.RedirectLocation)

					isRedirectMatch := (resp.StatusCode >= 300 && resp.StatusCode < 400) &&
						sigBaseLoc != "" && (baseLoc == sigBaseLoc || strings.TrimRight(baseLoc, "/") == strings.TrimRight(sigBaseLoc, "/"))

					// Hash match or tight size match
					isBodyMatch := (sig.BodyHash != "" && bHash != "" && sig.BodyHash == bHash) ||
						(diff <= 50 && (sig.Title == "" || sig.Title == title || (sig.BodySnippetHash != 0 && bodyHash == sig.BodySnippetHash)))

					// SPECIAL RULE FOR 403 / 401: If body hash is DIFFERENT and size differs by > 50, do NOT suppress!
					if resp.StatusCode == 403 || resp.StatusCode == 401 {
						if sig.BodyHash != "" && bHash != "" && sig.BodyHash != bHash && diff > 50 {
							isBodyMatch = false
						}
					}

					if isRedirectMatch || isBodyMatch {
						// Only allow 200 OK responses through if they contain genuine secret leaks or distinct debug output
						if !(resp.StatusCode == 200 && (len(leaks) > 0 || (title != sig.Title && title != ""))) {
							return nil
						}
					}
				}
			}
		}

		// 2. Sensitive classification logic:
		// - Redirects (301, 302, 303, 307, 308) are NEVER marked as sensitive!
		// - 401 / 403 are only sensitive on a site that does NOT wildcard 401/403.
		if isSensitive {
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				isSensitive = false
			} else if resp.StatusCode == 401 || resp.StatusCode == 403 {
				// Suppress sensitivity if site has 401/403 baseline
				if baseline.IsCatchAll {
					for _, sig := range baseline.Signatures {
						if sig.StatusCode == resp.StatusCode {
							isSensitive = false
							break
						}
					}
					if baseline.StatusCode == resp.StatusCode {
						isSensitive = false
					}
				}
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

// FuzzSingleURLWithRobotsBypass tests paths extracted from robots.txt with looser filter so catch-all won't easily suppress them.
func FuzzSingleURLWithRobotsBypass(client *http.Client, baseURL, path string, limiter *rate.Limiter, baseline BaselineResponse, targetHost string, defaultMethods []string) *core.DirFuzzFinding {
	if limiter != nil {
		_ = limiter.Wait(context.Background())
	}

	cleanPath := strings.TrimPrefix(path, "/")
	url := fmt.Sprintf("%s/%s", strings.TrimSuffix(baseURL, "/"), cleanPath)
	start := time.Now()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	if targetHost != "" {
		req.Host = targetHost
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SpecterRecon/0.9.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil
	}

	latency := float64(time.Since(start).Nanoseconds()) / 1e6
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	bodyStr := string(bodyBytes)
	contentLen := int64(len(bodyBytes))
	bHash := computeMD5Hash(bodyBytes)

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
	}

	if debugMode != "" {
		isSensitive = true
		if title == "" {
			title = "[" + debugMode + "]"
		} else {
			title = title + " [" + debugMode + "]"
		}
	}

	// Catch-All bypass check: only suppress if status code AND body hash match baseline exactly
	if baseline.IsCatchAll {
		sigsToCheck := baseline.Signatures
		if len(sigsToCheck) == 0 {
			sigsToCheck = []BaselineSignature{{
				StatusCode:       baseline.StatusCode,
				ContentLength:    baseline.ContentLength,
				RedirectLocation: baseline.RedirectLocation,
				Title:            baseline.Title,
				BodyHash:         baseline.BodyHash,
			}}
		}

		for _, sig := range sigsToCheck {
			if resp.StatusCode == sig.StatusCode {
				if sig.BodyHash != "" && bHash != "" && sig.BodyHash == bHash {
					return nil
				}
				diff := contentLen - sig.ContentLength
				if diff < 0 {
					diff = -diff
				}
				if diff == 0 && (sig.Title == "" || sig.Title == title) {
					return nil
				}
			}
		}
	}

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
		Path:             "/" + cleanPath,
		StatusCode:       resp.StatusCode,
		ContentLength:    contentLen,
		RedirectLocation: location,
		Title:            title,
		ResponseTimeMs:   &latency,
		IsSensitive:      isSensitive,
		WordlistMatched:  "robots.txt",
		MatchedTech:      "robots.txt",
		AllowedMethods:   allowedMethods,
	}
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

	// 4.1 Dedicated Robots.txt Bypass Scan
	var findings []core.DirFuzzFinding
	var mu sync.Mutex
	seenPathsMap := make(map[string]bool)

	if len(robotsPaths) > 0 {
		for _, rp := range robotsPaths {
			if rRes := FuzzSingleURLWithRobotsBypass(client, baseURL, rp, limiter, baseline, targetHost, rootAllowedMethods); rRes != nil {
				findings = append(findings, *rRes)
				seenPathsMap[rRes.Path] = true
				core.LogSuccess("robots.txt Yolu Doğrulandı: [%d] %s (Boyut: %dB)", rRes.StatusCode, rRes.URL, rRes.ContentLength)
			}
		}
	}

	wordChan := make(chan string, totalWords)
	for _, w := range enrichedWordlist {
		wordChan <- w
	}
	close(wordChan)

	var (
		wg               sync.WaitGroup
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
					// Bucketize response size into 45-byte intervals and include normalized redirect base path
					sizeBucket := (res.ContentLength / 45) * 45
					rBaseLoc := normalizeRedirectLocation(res.RedirectLocation)
					freqKey := fmt.Sprintf("%d:%d:%s", res.StatusCode, sizeBucket, rBaseLoc)

					mu.Lock()
					if seenPathsMap[res.Path] {
						mu.Unlock()
						continue
					}

					sizeFrequencyMap[freqKey]++
					count := sizeFrequencyMap[freqKey]

					// If any non-200 status (e.g. 302, 401, 403, 500) repeats more than 5 times with similar signature:
					if res.StatusCode != 200 && count > 5 {
						if count == 6 {
							// Prune earlier findings matching this repetitive wildcard signature
							var pruned []core.DirFuzzFinding
							for _, f := range findings {
								fBaseLoc := normalizeRedirectLocation(f.RedirectLocation)
								fKey := fmt.Sprintf("%d:%d:%s", f.StatusCode, (f.ContentLength/45)*45, fBaseLoc)
								if fKey != freqKey {
									pruned = append(pruned, f)
								}
							}
							findings = pruned
							core.LogWarning("Dinamik Catch-All / Wildcard Frekans Filtresi Tetiklendi: Hedef bilinmeyen yollara [%d] (~%dB) dönüyor. Tekrarlayan sahte yanıtlar engelleniyor.", res.StatusCode, res.ContentLength)
						}
						mu.Unlock()
						continue // Suppress repetitive wildcard / catch-all flood
					}

					seenPathsMap[res.Path] = true
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
		"owa": true, "ecp": true, "ews": true, "autodiscover": true, "elmah": true,
		"swagger": true, "actuator": true, "_layouts": true, "aspnet_client": true, "certsrv": true, "rpc": true,
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

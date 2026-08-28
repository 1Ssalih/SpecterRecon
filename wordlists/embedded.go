package wordlists

import (
	_ "embed"
	"path/filepath"
	"strings"
)

// Embedded core wordlists for 100% standalone binary execution across all operating systems.

//go:embed common.txt
var CommonTxt string

//go:embed sensitive.txt
var SensitiveTxt string

//go:embed apache.txt
var ApacheTxt string

//go:embed iis.txt
var IISTxt string

//go:embed aspnet.txt
var AspNetTxt string

//go:embed nginx.txt
var NginxTxt string

//go:embed tomcat.txt
var TomcatTxt string

//go:embed springboot.txt
var SpringBootTxt string

//go:embed php.txt
var PHPTxt string

//go:embed api.txt
var ApiTxt string

//go:embed django.txt
var DjangoTxt string

//go:embed jenkins.txt
var JenkinsTxt string

//go:embed nextjs.txt
var NextjsTxt string

//go:embed rails.txt
var RailsTxt string

//go:embed subdomains.txt
var SubdomainsTxt string

//go:embed wordpress.txt
var WordpressTxt string

//go:embed service_wordlist_map.yaml
var ServiceWordlistMapYAML string

// ParseWordlistString parses a raw newline-delimited wordlist string into cleaned words.
func ParseWordlistString(content string) []string {
	var words []string
	lines := strings.Split(content, "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			words = append(words, strings.TrimPrefix(trimmed, "/"))
		}
	}
	return words
}

// GetEmbeddedWordlist attempts to match a requested wordlist filename to an embedded memory asset.
func GetEmbeddedWordlist(path string) ([]string, bool) {
	base := strings.ToLower(filepath.Base(path))
	pLower := strings.ToLower(path)

	switch {
	case strings.Contains(base, "sensitive"):
		return ParseWordlistString(SensitiveTxt), true
	case strings.Contains(base, "iis") || strings.Contains(pLower, "iis.txt"):
		return ParseWordlistString(IISTxt), true
	case strings.Contains(base, "aspnet") || strings.Contains(base, "asp") || strings.Contains(pLower, "commonbackdoors-asp"):
		return ParseWordlistString(AspNetTxt), true
	case strings.Contains(base, "nginx"):
		return ParseWordlistString(NginxTxt), true
	case strings.Contains(base, "tomcat"):
		return ParseWordlistString(TomcatTxt), true
	case strings.Contains(base, "springboot") || strings.Contains(base, "spring-boot"):
		return ParseWordlistString(SpringBootTxt), true
	case strings.Contains(base, "php"):
		return ParseWordlistString(PHPTxt), true
	case strings.Contains(base, "apache"):
		return ParseWordlistString(ApacheTxt), true
	case strings.Contains(base, "api"):
		return ParseWordlistString(ApiTxt), true
	case strings.Contains(base, "django"):
		return ParseWordlistString(DjangoTxt), true
	case strings.Contains(base, "jenkins"):
		return ParseWordlistString(JenkinsTxt), true
	case strings.Contains(base, "nextjs"):
		return ParseWordlistString(NextjsTxt), true
	case strings.Contains(base, "rails"):
		return ParseWordlistString(RailsTxt), true
	case strings.Contains(base, "subdomain"):
		return ParseWordlistString(SubdomainsTxt), true
	case strings.Contains(base, "wordpress"):
		return ParseWordlistString(WordpressTxt), true
	case strings.Contains(base, "common") || strings.Contains(base, "raft"):
		return ParseWordlistString(CommonTxt), true
	default:
		return ParseWordlistString(CommonTxt), false
	}
}

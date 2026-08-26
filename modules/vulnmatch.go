package modules

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

const NVDAPIURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type OfflineCVE struct {
	Service      string
	VersionRegex *regexp.Regexp
	CVEID        string
	CVSSScore    float64
	Severity     string
	Description  string
	Mitigation   string
	References   []string
}

var OfflineCVEDatabase = []OfflineCVE{
	// Apache HTTP Server
	{
		Service:      "apache",
		VersionRegex: regexp.MustCompile(`2\.4\.49`),
		CVEID:        "CVE-2021-41773",
		CVSSScore:    7.5,
		Severity:     "HIGH",
		Description:  "Path traversal and remote code execution in Apache HTTP Server 2.4.49 via unmapped URLs.",
		Mitigation:   "Upgrade to Apache 2.4.51 or later.",
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
	},
	{
		Service:      "apache",
		VersionRegex: regexp.MustCompile(`2\.4\.50`),
		CVEID:        "CVE-2021-42013",
		CVSSScore:    9.8,
		Severity:     "CRITICAL",
		Description:  "Incomplete fix for CVE-2021-41773 allows remote code execution in Apache HTTP Server 2.4.50.",
		Mitigation:   "Upgrade to Apache 2.4.51 or later.",
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-42013"},
	},
	{
		Service:      "apache",
		VersionRegex: regexp.MustCompile(`2\.4\.(?:[0-9]|[1-3][0-9]|4[0-8])`),
		CVEID:        "CVE-2021-40438",
		CVSSScore:    9.0,
		Severity:     "CRITICAL",
		Description:  "Apache HTTP Server mod_proxy SSRF vulnerability allowing remote attackers to route arbitrary requests.",
		Mitigation:   "Upgrade to Apache HTTP Server 2.4.49+.",
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-40438"},
	},
	// OpenSSH
	{
		Service:      "ssh",
		VersionRegex: regexp.MustCompile(`7\.[0-6]`),
		CVEID:        "CVE-2018-15473",
		CVSSScore:    5.3,
		Severity:     "MEDIUM",
		Description:  "OpenSSH user enumeration vulnerability via malformed authentication requests.",
		Mitigation:   "Upgrade to OpenSSH 7.8 or newer.",
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-15473"},
	},
	{
		Service:      "ssh",
		VersionRegex: regexp.MustCompile(`9\.[0-7]p1`),
		CVEID:        "CVE-2024-6387",
		CVSSScore:    8.1,
		Severity:     "HIGH",
		Description:  "regreSSHion: Remote Unauthenticated Code Execution in OpenSSH server (sshd) on glibc-based Linux systems.",
		Mitigation:   "Upgrade to OpenSSH 9.8p1 or later.",
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-6387"},
	},
	// vsftpd
	{
		Service:      "ftp",
		VersionRegex: regexp.MustCompile(`2\.3\.4`),
		CVEID:        "CVE-2011-2523",
		CVSSScore:    9.8,
		Severity:     "CRITICAL",
		Description:  "vsftpd 2.3.4 Backdoor Command Execution triggered by smile smiley ':)' in username.",
		Mitigation:   "Replace with authentic vsftpd release 3.0+.",
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2011-2523"},
	},
	// ProFTPD
	{
		Service:      "ftp",
		VersionRegex: regexp.MustCompile(`1\.3\.5`),
		CVEID:        "CVE-2015-3306",
		CVSSScore:    9.8,
		Severity:     "CRITICAL",
		Description:  "The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read/write arbitrary files via SITE CPFR/CPTO.",
		Mitigation:   "Upgrade to ProFTPD 1.3.6+ or disable mod_copy.",
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2015-3306"},
	},
	// MySQL
	{
		Service:      "mysql",
		VersionRegex: regexp.MustCompile(`5\.[0-7]\.`),
		CVEID:        "CVE-2016-6662",
		CVSSScore:    9.8,
		Severity:     "CRITICAL",
		Description:  "MySQL Remote Root Code Execution / Privilege Escalation via configuration injection.",
		Mitigation:   "Apply official Oracle MySQL security patches.",
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2016-6662"},
	},
	// Redis
	{
		Service:      "redis",
		VersionRegex: regexp.MustCompile(`[456]\.`),
		CVEID:        "CVE-2022-0543",
		CVSSScore:    10.0,
		Severity:     "CRITICAL",
		Description:  "Redis Lua sandbox escape leading to Remote Code Execution via package.loadlib in Debian/Ubuntu packages.",
		Mitigation:   "Upgrade Redis package and enable protected-mode.",
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-0543"},
	},
	// PHP
	{
		Service:      "http",
		VersionRegex: regexp.MustCompile(`8\.1\.0-dev`),
		CVEID:        "CVE-2021-00001",
		CVSSScore:    9.8,
		Severity:     "CRITICAL",
		Description:  "PHP 8.1.0-dev Backdoor Remote Code Execution via User-Agentt header.",
		Mitigation:   "Reinstall legitimate PHP build.",
		References:   []string{"https://github.com/vulhub/vulhub/tree/master/php/8.1-backdoor"},
	},
}

// CVSSToSeverity maps float CVSS score to severity rating.
func CVSSToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0.0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// MatchOfflineCVEs matches service info against offline database.
func MatchOfflineCVEs(svc core.ServiceDetail) []core.VulnerabilityInfo {
	var vulns []core.VulnerabilityInfo
	sName := strings.ToLower(svc.ServiceName)
	sDesc := strings.ToLower(svc.ServiceDescription)
	sVer := svc.ServiceVersion

	for _, item := range OfflineCVEDatabase {
		dbService := strings.ToLower(item.Service)
		if strings.Contains(sName, dbService) || strings.Contains(sDesc, dbService) {
			if sVer != "" && item.VersionRegex.MatchString(sVer) {
				vulns = append(vulns, core.VulnerabilityInfo{
					CVEID:           item.CVEID,
					CVSSScore:       item.CVSSScore,
					Severity:        item.Severity,
					Description:     item.Description,
					AffectedService: fmt.Sprintf("%s (%s:%d)", svc.ServiceName, svc.IP, svc.Port),
					AffectedVersion: sVer,
					PublishedDate:   "N/A",
					References:      item.References,
					Mitigation:      item.Mitigation,
				})
			}
		}
	}
	return vulns
}

// QueryNVDAPI queries official NVD API v2 for keyword.
func QueryNVDAPI(keyword, apiKey string, maxResults int) ([]core.VulnerabilityInfo, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	reqURL := fmt.Sprintf("%s?keywordSearch=%s&resultsPerPage=%d", NVDAPIURL, url.QueryEscape(keyword), maxResults)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SpecterRecon/1.0 (Security Assessment)")
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD API HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var nvdResponse struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CVSSMetricV30 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
					CVSSMetricV2 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &nvdResponse); err != nil {
		return nil, err
	}

	var results []core.VulnerabilityInfo
	for _, item := range nvdResponse.Vulnerabilities {
		cve := item.CVE
		desc := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		if desc == "" && len(cve.Descriptions) > 0 {
			desc = cve.Descriptions[0].Value
		}

		score := 0.0
		if len(cve.Metrics.CVSSMetricV31) > 0 {
			score = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
		} else if len(cve.Metrics.CVSSMetricV30) > 0 {
			score = cve.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
		} else if len(cve.Metrics.CVSSMetricV2) > 0 {
			score = cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
		}

		var refs []string
		for _, r := range cve.References {
			if r.URL != "" {
				refs = append(refs, r.URL)
				if len(refs) >= 3 {
					break
				}
			}
		}

		if len(desc) > 300 {
			desc = desc[:297] + "..."
		}

		results = append(results, core.VulnerabilityInfo{
			CVEID:           cve.ID,
			CVSSScore:       score,
			Severity:        CVSSToSeverity(score),
			Description:     desc,
			AffectedService: keyword,
			PublishedDate:   cve.Published,
			References:      refs,
		})
	}

	return results, nil
}

// MatchVulnerabilities performs vulnerability matching against offline DB and NVD API.
func MatchVulnerabilities(services []core.ServiceDetail, apiKey string, useOnlineAPI bool, outputFile string) ([]core.VulnerabilityInfo, error) {
	core.LogInfo("CVE & Zafiyet Eşleştirmesi başlatılıyor (%d servis)...", len(services))
	core.LogAudit("VULN_MATCH_START", fmt.Sprintf("services=%d", len(services)), "", "SUCCESS")

	var allVulns []core.VulnerabilityInfo
	seenCVEs := make(map[string]bool)

	for _, svc := range services {
		// 1. Offline Database Matching
		offlineMatches := MatchOfflineCVEs(svc)
		for _, v := range offlineMatches {
			if !seenCVEs[v.CVEID] {
				seenCVEs[v.CVEID] = true
				allVulns = append(allVulns, v)
				core.LogWarning("Zafiyet Tespit Edildi (Offline DB): %s [%s - CVSS: %.1f] -> %s", v.CVEID, v.Severity, v.CVSSScore, v.AffectedService)
			}
		}

		// 2. Online NVD API Query
		if useOnlineAPI && svc.ServiceVersion != "" && svc.ServiceName != "unknown" {
			query := fmt.Sprintf("%s %s", svc.ServiceName, svc.ServiceVersion)
			core.LogInfo("NVD API sorgulanıyor: '%s'...", query)
			nvdResults, err := QueryNVDAPI(query, apiKey, 5)
			if err == nil {
				for _, v := range nvdResults {
					if !seenCVEs[v.CVEID] {
						v.AffectedService = fmt.Sprintf("%s (%s:%d)", svc.ServiceName, svc.IP, svc.Port)
						v.AffectedVersion = svc.ServiceVersion
						seenCVEs[v.CVEID] = true
						allVulns = append(allVulns, v)
						core.LogWarning("Zafiyet Tespit Edildi (NVD API): %s [%s - CVSS: %.1f] -> %s", v.CVEID, v.Severity, v.CVSSScore, v.AffectedService)
					}
				}
			}
			time.Sleep(600 * time.Millisecond)
		}
	}

	sort.Slice(allVulns, func(i, j int) bool {
		return allVulns[i].CVSSScore > allVulns[j].CVSSScore
	})

	if outputFile != "" {
		_ = core.SaveVulns(allVulns, outputFile)
	}

	core.LogInfo("CVE Analizi tamamlandı: %d zafiyet bulundu (%s).", len(allVulns), outputFile)
	core.LogAudit("VULN_MATCH_COMPLETE", "all", fmt.Sprintf("total_vulns=%d", len(allVulns)), "SUCCESS")

	return allVulns, nil
}

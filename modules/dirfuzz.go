package modules

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/specter-recon/recon-tool/core"
	"gopkg.in/yaml.v3"
)

var SensitiveKeywords = []string{".env", ".git", ".bak", "config", "backup", "sql", "id_rsa", "password", "secret", "private"}

type WordlistConfigFile struct {
	Quick map[string]string `yaml:"quick"`
	Full  map[string]string `yaml:"full"`
}

// LoadServiceWordlistMap loads the service-to-wordlist configuration map for the specified sizeMode ("quick" or "full").
func LoadServiceWordlistMap(mapFile, sizeMode string) map[string]string {
	if mapFile == "" {
		mapFile = "wordlists/service_wordlist_map.yaml"
	}
	if sizeMode == "" {
		sizeMode = "quick"
	}

	result := make(map[string]string)
	data, err := os.ReadFile(mapFile)
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
				"jenkins":   "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Jenkins-Hudson.txt",
				"apache":    "wordlists/SecLists/Discovery/Web-Content/Web-Servers/Apache.txt",
				"iis":       "wordlists/SecLists/Discovery/Web-Content/Web-Servers/IIS.txt",
				"nginx":     "wordlists/SecLists/Discovery/Web-Content/Web-Servers/nginx.txt",
				"tomcat":    "wordlists/SecLists/Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt",
				"wordpress": "wordlists/SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
				"default":   "wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt",
			}
		} else {
			result = map[string]string{
				"jenkins":   "wordlists/jenkins.txt",
				"apache":    "wordlists/apache.txt",
				"wordpress": "wordlists/wordpress.txt",
				"iis":       "wordlists/SecLists/Discovery/Web-Content/Web-Servers/IIS.txt",
				"nginx":     "wordlists/SecLists/Discovery/Web-Content/Web-Servers/nginx.txt",
				"tomcat":    "wordlists/SecLists/Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt",
				"default":   "wordlists/common.txt",
			}
		}
	}

	return result
}

// SelectWordlistForService selects the most relevant wordlist for a detected HTTP service using advanced technology detection.
func SelectWordlistForService(svc core.ServiceDetail, wordlistMap map[string]string, defaultWordlist string) (string, string) {
	if defaultWordlist == "" {
		defaultWordlist = "wordlists/common.txt"
	}
	if wordlistMap == nil {
		wordlistMap = LoadServiceWordlistMap("", "quick")
	}

	// Yeni: Gelişmiş teknoloji tespiti kullanarak en yüksek güven skoruna sahip teknolojiyi seç
	techMatches := DetectTechnologiesFromBanner(svc)
	
	if len(techMatches) > 0 {
		// En yüksek confidence skorlu teknolojiyi kullan
		bestMatch := techMatches[0]
		core.LogInfo("🎯 Teknoloji Tespit Edildi: %s (Güven: %.0f%%, Kategori: %s)", 
			bestMatch.Name, bestMatch.Confidence*100, bestMatch.Category)
		
		if path, ok := wordlistMap[bestMatch.Name]; ok {
			if _, err := os.Stat(path); err == nil {
				return path, bestMatch.Name
			}
			core.LogWarning("Wordlist bulunamadı: %s (kategori: %s), varsayılana düşülüyor", path, bestMatch.Name)
		}
	}

	// Fallback: Eski string-based matching
	haystack := strings.ToLower(fmt.Sprintf("%s %s %s %s %s",
		svc.ServiceName,
		svc.ServiceDescription,
		svc.HTTPTitle,
		svc.HTTPServer,
		strings.Join(svc.HTTPTechnologies, " "),
	))

	// Fixed priority order — specific CMS and servers first
	priorityOrder := []string{
		"wordpress", "jenkins", "apache", "nginx", "tomcat", "iis", "drupal", "joomla",
		"sharepoint", "springboot", "php", "aspnet", "gitlab", "grafana", "elasticsearch", "swagger", "api",
	}

	for _, key := range priorityOrder {
		path, ok := wordlistMap[key]
		if !ok {
			continue
		}

		matched := false
		if key == "springboot" {
			matched = strings.Contains(haystack, "spring") || strings.Contains(haystack, "boot")
		} else if key == "aspnet" {
			matched = strings.Contains(haystack, "asp.net") || strings.Contains(haystack, "aspnet")
		} else if key == "iis" {
			matched = strings.Contains(haystack, "iis") || strings.Contains(haystack, "microsoft-iis")
		} else {
			matched = strings.Contains(haystack, key)
		}

		if matched {
			if _, err := os.Stat(path); err == nil {
				return path, key
			}
			core.LogWarning("Wordlist bulunamadı: %s (kategori: %s), varsayılana düşülüyor", path, key)
		}
	}

	// Check any other custom keys in the map
	for key, path := range wordlistMap {
		if key == "default" {
			continue
		}
		alreadyChecked := false
		for _, pk := range priorityOrder {
			if pk == key {
				alreadyChecked = true
				break
			}
		}
		if alreadyChecked {
			continue
		}
		if strings.Contains(haystack, strings.ToLower(key)) {
			if _, err := os.Stat(path); err == nil {
				return path, key
			}
			core.LogWarning("Wordlist bulunamadı: %s (kategori: %s), varsayılana düşülüyor", path, key)
		}
	}

	if defPath, ok := wordlistMap["default"]; ok {
		if _, err := os.Stat(defPath); err == nil {
			return defPath, "default"
		}
	}

	return defaultWordlist, "common"
}

// LoadWordlist reads paths from wordlist file.
func LoadWordlist(filepath string) []string {
	file, err := os.Open(filepath)
	if err != nil {
		core.LogWarning("Wordlist dosyası bulunamadı: %s", filepath)
		return nil
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, strings.TrimPrefix(line, "/"))
		}
	}
	return words
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

// FuzzSingleURL requests a single path and evaluates response.
func FuzzSingleURL(client *http.Client, baseURL, path, matchTag string, statusFilter map[int]bool, delayMs int) *core.DirFuzzFinding {
	if delayMs > 0 {
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}

	url := fmt.Sprintf("%s/%s", strings.TrimSuffix(baseURL, "/"), path)
	start := time.Now()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SpecterRecon/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	latency := float64(time.Since(start).Nanoseconds()) / 1e6

	if statusFilter[resp.StatusCode] {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		bodyStr := string(bodyBytes)

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

		return &core.DirFuzzFinding{
			URL:              url,
			Path:             "/" + path,
			StatusCode:       resp.StatusCode,
			ContentLength:    int64(len(bodyBytes)),
			RedirectLocation: location,
			Title:            title,
			ResponseTimeMs:   &latency,
			IsSensitive:      isSensitive,
			WordlistMatched:  matchTag,
		}
	}

	return nil
}

// FuzzTargetService runs concurrent directory fuzzing against a single base URL.
func FuzzTargetService(baseURL string, wordlist []string, matchTag string, concurrency int, delayMs int) []core.DirFuzzFinding {
	totalWords := len(wordlist)
	core.LogInfo("Dizin Taraması başlatılıyor: Hedef='%s', Liste='%s', Kelime Sayısı=%d", baseURL, matchTag, totalWords)
	core.LogAudit("DIR_FUZZ_START", baseURL, fmt.Sprintf("words=%d, matchTag=%s, concurrency=%d", totalWords, matchTag, concurrency), "SUCCESS")

	if concurrency <= 0 {
		concurrency = 25
	}

	statusFilter := map[int]bool{
		200: true, 204: true, 301: true, 302: true, 307: true, 308: true, 401: true, 403: true, 405: true, 500: true,
	}

	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
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

	wordChan := make(chan string, totalWords)
	for _, w := range wordlist {
		wordChan <- w
	}
	close(wordChan)

	var (
		wg             sync.WaitGroup
		mu             sync.Mutex
		findings       []core.DirFuzzFinding
		processedCount int64
		startTime      = time.Now()
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range wordChan {
				res := FuzzSingleURL(client, baseURL, w, matchTag, statusFilter, delayMs)
				curr := atomic.AddInt64(&processedCount, 1)

				if res != nil {
					mu.Lock()
					findings = append(findings, *res)
					mu.Unlock()

					tag := ""
					if res.IsSensitive {
						tag = " [KRİTİK DOSYA]"
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

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Path < findings[j].Path
	})

	return findings
}

// RunDirFuzzing orchestrates directory fuzzing across all open HTTP/HTTPS services with smart wordlists.
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

		// Smart wordlist selection
		selectedWordlistPath, matchKey := SelectWordlistForService(svc, wordlistMap, defaultWordlist)
		serviceWords := LoadWordlist(selectedWordlistPath)

		// Combine sensitive words with service words
		seen := make(map[string]bool)
		var combined []string
		for _, w := range append(sensitiveWords, serviceWords...) {
			if !seen[w] && w != "" {
				seen[w] = true
				combined = append(combined, w)
			}
		}

		core.LogInfo("Servis '%s:%d' için wordlist seçildi: %s (%s, toplam %d kelime)", svc.IP, svc.Port, filepath.Base(selectedWordlistPath), matchKey, len(combined))

		found := FuzzTargetService(baseURL, combined, matchKey, concurrency, delayMs)
		allFindings = append(allFindings, found...)
	}

	if outputJSON != "" || outputTxt != "" {
		_ = core.SaveFindings(allFindings, outputJSON, outputTxt)
	}

	core.LogInfo("Dizin Taraması tamamlandı: %d bulgu kaydedildi (%s & %s).", len(allFindings), outputJSON, outputTxt)
	core.LogAudit("DIR_FUZZ_COMPLETE", "all", fmt.Sprintf("total_findings=%d", len(allFindings)), "SUCCESS")

	return allFindings, nil
}

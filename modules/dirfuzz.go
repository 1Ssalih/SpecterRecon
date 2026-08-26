package modules

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

var SensitiveKeywords = []string{".env", ".git", ".bak", "config", "backup", "sql", "id_rsa", "password", "secret", "private"}

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
func FuzzSingleURL(client *http.Client, baseURL, path string, statusFilter map[int]bool, delayMs int) *core.DirFuzzFinding {
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
		}
	}

	return nil
}

// FuzzTargetService runs concurrent directory fuzzing against a single base URL.
func FuzzTargetService(baseURL string, wordlist []string, concurrency int, delayMs int) []core.DirFuzzFinding {
	core.LogInfo("Dizin Taraması başlatılıyor: Hedef='%s', Kelime Sayısı=%d", baseURL, len(wordlist))
	core.LogAudit("DIR_FUZZ_START", baseURL, fmt.Sprintf("words=%d, concurrency=%d", len(wordlist), concurrency), "SUCCESS")

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

	wordChan := make(chan string, len(wordlist))
	for _, w := range wordlist {
		wordChan <- w
	}
	close(wordChan)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		findings []core.DirFuzzFinding
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range wordChan {
				res := FuzzSingleURL(client, baseURL, w, statusFilter, delayMs)
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
			}
		}()
	}

	wg.Wait()

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Path < findings[j].Path
	})

	return findings
}

// RunDirFuzzing orchestrates directory fuzzing across all open HTTP/HTTPS services.
func RunDirFuzzing(services []core.ServiceDetail, wordlistPath, sensitivePath string, concurrency int, delayMs int, outputJSON, outputTxt string) ([]core.DirFuzzFinding, error) {
	if wordlistPath == "" {
		wordlistPath = "wordlists/common.txt"
	}
	if sensitivePath == "" {
		sensitivePath = "wordlists/sensitive.txt"
	}

	words := LoadWordlist(wordlistPath)
	sensitiveWords := LoadWordlist(sensitivePath)

	seen := make(map[string]bool)
	var combined []string
	for _, w := range append(sensitiveWords, words...) {
		if !seen[w] {
			seen[w] = true
			combined = append(combined, w)
		}
	}

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

	core.LogInfo("Toplam %d HTTP/HTTPS servisi taranacak.", len(httpServices))
	var allFindings []core.DirFuzzFinding

	for _, svc := range httpServices {
		proto := "http"
		if svc.SSLEnabled || svc.Port == 443 || svc.Port == 8443 {
			proto = "https"
		}
		baseURL := fmt.Sprintf("%s://%s:%d", proto, svc.IP, svc.Port)

		found := FuzzTargetService(baseURL, combined, concurrency, delayMs)
		allFindings = append(allFindings, found...)
	}

	if outputJSON != "" || outputTxt != "" {
		_ = core.SaveFindings(allFindings, outputJSON, outputTxt)
	}

	core.LogInfo("Dizin Taraması tamamlandı: %d bulgu kaydedildi (%s & %s).", len(allFindings), outputJSON, outputTxt)
	core.LogAudit("DIR_FUZZ_COMPLETE", "all", fmt.Sprintf("total_findings=%d", len(allFindings)), "SUCCESS")

	return allFindings, nil
}

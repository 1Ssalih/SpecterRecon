package modules

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

func TestIsDomainName(t *testing.T) {
	if !IsDomainName("example.com") {
		t.Errorf("example.com domain olarak taninmali")
	}
	if !IsDomainName("scanme.nmap.org") {
		t.Errorf("scanme.nmap.org domain olarak taninmali")
	}
	if IsDomainName("192.168.1.1") {
		t.Errorf("192.168.1.1 IP olmali, domain degil")
	}
	if IsDomainName("10.0.0.0/24") {
		t.Errorf("10.0.0.0/24 CIDR olmali, domain degil")
	}
}

func TestSmartWordlistSelection(t *testing.T) {
	wordlistMap := map[string]string{
		"apache":     "../wordlists/apache.txt",
		"jenkins":    "../wordlists/jenkins.txt",
		"wordpress":  "../wordlists/wordpress.txt",
		"springboot": "../wordlists/SecLists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt",
		"nginx":      "../wordlists/SecLists/Discovery/Web-Content/Web-Servers/nginx.txt",
		"default":    "../wordlists/common.txt",
	}

	apacheSvc := core.ServiceDetail{
		ServiceName:        "http",
		ServiceDescription: "Apache HTTP Server 2.4.49",
	}
	wPaths, key := SelectWordlistForService(apacheSvc, wordlistMap, "../wordlists/common.txt")
	if !strings.Contains(key, "apache") || len(wPaths) == 0 || !strings.Contains(wPaths[0], "apache.txt") {
		t.Errorf("Apache servisi icin apache.txt secilmeli, alinan: key=%s, paths=%v", key, wPaths)
	}

	unknownSvc := core.ServiceDetail{
		ServiceName:        "http",
		ServiceDescription: "Unknown Custom Server",
	}
	wPaths2, key2 := SelectWordlistForService(unknownSvc, wordlistMap, "../wordlists/common.txt")
	if key2 != "default" && key2 != "common" {
		t.Errorf("Bilinmeyen servis varsayilana dusmeli, alinan: key=%s, paths=%v", key2, wPaths2)
	}

	// Hem apache hem wordpress iceren servis: WordPress (Tier 1) ve Apache (Tier 4) listeleri donmeli, Tier 1 ilk sirada olmali
	wpApacheSvc := core.ServiceDetail{
		ServiceName:        "http",
		ServiceDescription: "WordPress on Apache",
		HTTPServer:         "Apache/2.4.49",
	}
	wPaths3, key3 := SelectWordlistForService(wpApacheSvc, wordlistMap, "../wordlists/common.txt")
	if !strings.Contains(key3, "wordpress") || len(wPaths3) == 0 || !strings.Contains(wPaths3[0], "wordpress.txt") {
		t.Errorf("WordPress+Apache servisinde wordpress.txt ilk sirada olmali, alinan: key=%s, paths=%v", key3, wPaths3)
	}
}

func TestSpringBootBehindNginxScenario(t *testing.T) {
	wordlistMap := map[string]string{
		"springboot": "../wordlists/SecLists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt",
		"nginx":      "../wordlists/SecLists/Discovery/Web-Content/Web-Servers/nginx.txt",
		"default":    "../wordlists/common.txt",
	}

	// Nginx arkasında çalışan Spring Boot servisi simülasyonu
	svc := core.ServiceDetail{
		ServiceName:        "http",
		HTTPServer:         "nginx/1.18.0 (Ubuntu)",
		DetectedTechs:      []string{"springboot", "nginx"},
		ServiceDescription: "Whitelabel Error Page - Spring Boot",
	}

	wPaths, key := SelectWordlistForService(svc, wordlistMap, "../wordlists/common.txt")
	if len(wPaths) < 2 {
		t.Fatalf("Nginx arkasında Spring Boot senaryosunda her iki katman da seçilmeli, alinan sayi: %d (paths: %v)", len(wPaths), wPaths)
	}

	// Tier 2 (springboot) Tier 4'ten (nginx) önce gelmeli
	if !strings.Contains(wPaths[0], "Java-Spring-Boot.txt") {
		t.Errorf("İlk sırada Spring Boot wordlist'i bekleniyordu, alinan: %s", wPaths[0])
	}
	if !strings.Contains(wPaths[1], "nginx.txt") {
		t.Errorf("İkinci sırada Nginx wordlist'i bekleniyordu, alinan: %s", wPaths[1])
	}
	if !strings.Contains(key, "springboot") || !strings.Contains(key, "nginx") {
		t.Errorf("Matched key 'springboot+nginx' içermeli, alinan: %s", key)
	}
}

func TestMergeUnique(t *testing.T) {
	list1 := []string{"admin", "login", "/api", "docs"}
	list2 := []string{"login", "users", "# comment line", "", "  api  "}
	list3 := []string{"docs", "actuator/health", "admin"}

	merged := MergeUnique(list1, list2, list3)
	expected := []string{"admin", "login", "api", "docs", "users", "actuator/health"}

	if len(merged) != len(expected) {
		t.Fatalf("MergeUnique uzunluk hatası: beklenen %d, alinan %d (%v)", len(expected), len(merged), merged)
	}
	for i, v := range expected {
		if merged[i] != v {
			t.Errorf("Index %d hatası: beklenen '%s', alinan '%s'", i, v, merged[i])
		}
	}
}

func TestParseTargets(t *testing.T) {
	single := ParseTargets("127.0.0.1")
	if len(single) != 1 || single[0] != "127.0.0.1" {
		t.Errorf("Beklenen [127.0.0.1], alinan %v", single)
	}

	rangeIPs := ParseTargets("192.168.1.1-192.168.1.3")
	if len(rangeIPs) != 3 || rangeIPs[0] != "192.168.1.1" || rangeIPs[2] != "192.168.1.3" {
		t.Errorf("Beklenen 3 IP, alinan %v", rangeIPs)
	}
}

func TestParsePortSpecs(t *testing.T) {
	top20 := ParsePortSpecs("top-20")
	if len(top20) != 20 {
		t.Errorf("top-20 port sayisi 20 olmali, alinan %d", len(top20))
	}

	custom := ParsePortSpecs("80,443,8000-8002")
	expected := []int{80, 443, 8000, 8001, 8002}
	if len(custom) != len(expected) {
		t.Errorf("Beklenen %v, alinan %v", expected, custom)
	}
}

func TestExtractVersionFromText(t *testing.T) {
	name, desc, ver := ExtractVersionFromText("Apache/2.4.49 (Unix) OpenSSL/1.1.1l")
	if name != "http" || ver != "2.4.49" {
		t.Errorf("Beklenen http v2.4.49, alinan %s %s %s", name, desc, ver)
	}

	name2, _, ver2 := ExtractVersionFromText("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
	if name2 != "ssh" || ver2 != "8.9p1" {
		t.Errorf("Beklenen ssh v8.9p1, alinan %s %s", name2, ver2)
	}

	name3, _, ver3 := ExtractVersionFromText("220 (vsFTPd 2.3.4)")
	if name3 != "ftp" || ver3 != "2.3.4" {
		t.Errorf("Beklenen ftp v2.3.4, alinan %s %s", name3, ver3)
	}
}

func TestSanitizeBanner(t *testing.T) {
	raw := "SSH-2.0-OpenSSH_8.9p1\r\n\x00\x01\x02\x07Ubuntu"
	cleaned := SanitizeBanner(raw)
	if strings.Contains(cleaned, "\x00") || strings.Contains(cleaned, "\x01") || strings.Contains(cleaned, "\r") {
		t.Errorf("SanitizeBanner non-printable karakterleri temizleyemedi: %q", cleaned)
	}
	if !strings.Contains(cleaned, "SSH-2.0-OpenSSH_8.9p1") {
		t.Errorf("SanitizeBanner metin icerigini bozdu: %s", cleaned)
	}
}

func TestParseMySQLHandshake(t *testing.T) {
	// Simulated MySQL handshake packet:
	// Length: 36 (0x24 0x00 0x00), Seq: 0, Proto: 10 (0x0a), Version: "8.0.32-0ubuntu0.22.04.2\x00"
	mockPacket := []byte{
		0x24, 0x00, 0x00, 0x00, // length & seq
		0x0a,                                                                       // protocol version (10)
		'8', '.', '0', '.', '3', '2', '-', '0', 'u', 'b', 'u', 'n', 't', 'u', 0x00, // null-terminated version string
		0x01, 0x02, 0x03, 0x04, // auth data
	}

	name, desc, ver, banner := ParseMySQLHandshake(mockPacket)
	if name != "mysql" {
		t.Errorf("Beklenen servis adı 'mysql', alinan '%s'", name)
	}
	if ver != "8.0.32" {
		t.Errorf("Beklenen versiyon '8.0.32', alinan '%s'", ver)
	}
	if !strings.Contains(desc, "MySQL") {
		t.Errorf("Beklenen aciklama 'MySQL', alinan '%s'", desc)
	}
	if !strings.Contains(banner, "8.0.32-0ubuntu") {
		t.Errorf("Beklenen banner '8.0.32-0ubuntu', alinan '%s'", banner)
	}
}

func TestParseBinaryProtocolBanner(t *testing.T) {
	// 1. NetBIOS Port 139 Session
	mockNetBIOS := []byte{0x82, 0x00, 0x00, 0x00}
	sName, sDesc, _, banner, handled := ParseBinaryProtocolBanner(139, mockNetBIOS)
	if !handled || sName != "netbios-ssn" {
		t.Errorf("NetBIOS paketi taninamadi: handled=%v, sName=%s", handled, sName)
	}
	if !strings.Contains(sDesc, "NetBIOS") || !strings.Contains(banner, "NetBIOS") {
		t.Errorf("NetBIOS banner hatali: desc=%s, banner=%s", sDesc, banner)
	}

	// 2. Fortinet FSSO Port 8000
	mockFSSO := []byte{0x5a, 0x01, 'F', 'S', 'S', 'O', ' ', '5', '.', '0', '.', '0', '3', '1', '9', 0x00, 0x02}
	sName2, _, ver2, banner2, handled2 := ParseBinaryProtocolBanner(8000, mockFSSO)
	if !handled2 || sName2 != "fsso" {
		t.Errorf("FSSO paketi taninamadi: handled=%v, sName=%s", handled2, sName2)
	}
	if ver2 != "5.0.0319" || !strings.Contains(banner2, "FSSO") {
		t.Errorf("FSSO versiyon/banner hatali: ver=%s, banner=%s", ver2, banner2)
	}

	// 3. Unprintable random binary junk
	junk := []byte{0x01, 0x02, 0x03, 0x04, 0x80, 0x90, 0xfe, 0xff}
	_, _, _, banner3, handled3 := ParseBinaryProtocolBanner(5555, junk)
	if !handled3 || !strings.Contains(banner3, "[Binary Protocol Response]") {
		t.Errorf("Binary junk filtrelenemedi: handled=%v, banner=%s", handled3, banner3)
	}
}

func TestWordlistSizeMode(t *testing.T) {
	quickMap := LoadServiceWordlistMap("", "quick")
	if quickMap == nil || len(quickMap) == 0 {
		t.Fatalf("LoadServiceWordlistMap quick modu bos dondurdu")
	}

	fullMap := LoadServiceWordlistMap("", "full")
	if fullMap == nil || len(fullMap) == 0 {
		t.Fatalf("LoadServiceWordlistMap full modu bos dondurdu")
	}

	// Full mode must contain SecLists paths
	iisFull, ok := fullMap["iis"]
	if !ok || !strings.Contains(iisFull, "SecLists") {
		t.Errorf("Full modunda IIS icin SecLists yolu bekleniyordu, alinan: %s", iisFull)
	}
}

func TestReportGeneration(t *testing.T) {
	_ = os.MkdirAll("output/test", 0755)
	dns := core.DNSFinding{
		Hostname:   "test.local",
		IP:         "127.0.0.1",
		RecordType: "A",
		Source:     "root_resolution",
	}
	host := core.NewHostInfo("127.0.0.1", "tcp_ping")
	port := core.PortInfo{IP: "127.0.0.1", Port: 80, ServiceName: "http", State: "open"}
	svc := core.ServiceDetail{IP: "127.0.0.1", Port: 80, ServiceName: "http", ServiceVersion: "2.4.49"}
	finding := core.DirFuzzFinding{
		URL:             "http://127.0.0.1:80/admin",
		Path:            "/admin",
		StatusCode:      200,
		WordlistMatched: "apache",
	}

	report := BuildCompleteReport("test.local", []core.DNSFinding{dns}, []core.HostInfo{host}, []core.PortInfo{port}, []core.ServiceDetail{svc}, []core.DirFuzzFinding{finding}, 1.25)
	outPath, err := GenerateHTMLReport(report, "../templates/report.html.tmpl", "output/test/test_report.html")
	if err != nil {
		t.Fatalf("GenerateHTMLReport hatasi: %v", err)
	}

	if outPath == "" {
		t.Errorf("Rapor ciktisi bos döndü")
	}
}

func TestPassiveModulesInitialization(t *testing.T) {
	// 1. SSL Audit Test on unreachable port
	sslFinding := AuditSSLService("127.0.0.1", 59999, 100*time.Millisecond)
	if sslFinding.IP != "127.0.0.1" || sslFinding.Port != 59999 {
		t.Errorf("SSL Audit IP/Port hatali: %v", sslFinding)
	}

	// 2. HTTP Audit Test on unreachable port
	httpFinding := AuditHTTPService("127.0.0.1", 59999, false, 100*time.Millisecond)
	if httpFinding.IP != "127.0.0.1" || httpFinding.Port != 59999 {
		t.Errorf("HTTP Audit IP/Port hatali: %v", httpFinding)
	}
}

func TestWappalyzerStyleFingerprinting(t *testing.T) {
	// Test 1: WordPress via Meta Generator & wp-content
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.52")
		w.Header().Set("X-Powered-By", "PHP/8.1.2")
		fmt.Fprintln(w, `<html><head><meta name="generator" content="WordPress 6.2" /><title>My Blog</title></head><body><link rel="stylesheet" href="/wp-content/themes/style.css"></body></html>`)
	}))
	defer ts1.Close()

	u1, _ := url.Parse(ts1.URL)
	port1, _ := strconv.Atoi(u1.Port())
	res1 := ProbeHTTPService(u1.Hostname(), port1, false, 2*time.Second)

	hasWP := false
	hasPHP := false
	hasApache := false
	for _, tech := range res1.DetectedTechs {
		if tech == "wordpress" {
			hasWP = true
		}
		if tech == "php" {
			hasPHP = true
		}
		if tech == "apache" {
			hasApache = true
		}
	}
	if !hasWP || !hasPHP || !hasApache {
		t.Errorf("WordPress/PHP/Apache tespiti başarısız: %v", res1.DetectedTechs)
	}

	// Test 2: Next.js via __NEXT_DATA__
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Vercel")
		fmt.Fprintln(w, `<html><head><title>App</title></head><body><div id="__next"><script id="__NEXT_DATA__" type="application/json">{"props":{}}</script></div></body></html>`)
	}))
	defer ts2.Close()

	u2, _ := url.Parse(ts2.URL)
	port2, _ := strconv.Atoi(u2.Port())
	res2 := ProbeHTTPService(u2.Hostname(), port2, false, 2*time.Second)

	hasNext := false
	for _, tech := range res2.DetectedTechs {
		if tech == "nextjs" {
			hasNext = true
		}
	}
	if !hasNext {
		t.Errorf("Next.js __NEXT_DATA__ tespiti başarısız: %v", res2.DetectedTechs)
	}

	// Test 3: Spring Boot Whitelabel Error Page
	ts3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Application-Context", "application:production")
		fmt.Fprintln(w, `<html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error</p></body></html>`)
	}))
	defer ts3.Close()

	u3, _ := url.Parse(ts3.URL)
	port3, _ := strconv.Atoi(u3.Port())
	res3 := ProbeHTTPService(u3.Hostname(), port3, false, 2*time.Second)

	hasSpring := false
	hasNginx := false
	for _, tech := range res3.DetectedTechs {
		if tech == "springboot" {
			hasSpring = true
		}
		if tech == "nginx" {
			hasNginx = true
		}
	}
	if !hasSpring || !hasNginx {
		t.Errorf("Spring Boot + Nginx tespiti başarısız: %v", res3.DetectedTechs)
	}
}

func TestSensitiveKeywordsAccessDenied(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ".env") || strings.Contains(r.URL.Path, "backup.sql") {
			w.WriteHeader(http.StatusForbidden) // 403
			fmt.Fprintln(w, "Forbidden Access")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	statusFilter := map[int]bool{200: true, 401: true, 403: true}
	client := ts.Client()

	finding := FuzzSingleURL(client, ts.URL, ".env", "sensitive", statusFilter, nil, BaselineResponse{}, "", nil)
	if finding == nil {
		t.Fatalf("403 Forbidden dönen .env dosyası finding olarak yakalanamadı")
	}
	if !finding.IsSensitive {
		t.Errorf(".env dosyası IsSensitive=true olmalı")
	}
	if finding.StatusCode != 403 {
		t.Errorf("StatusCode 403 bekleniyordu, alinan: %d", finding.StatusCode)
	}
	if !strings.Contains(finding.Title, "Access Denied") {
		t.Errorf("Title 'Access Denied' içermeli, alinan: %s", finding.Title)
	}
	if finding.MatchedTech != "sensitive" {
		t.Errorf("MatchedTech 'sensitive' olmalı, alinan: %s", finding.MatchedTech)
	}
}

func TestRateLimiterIntegration(t *testing.T) {
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if strings.HasPrefix(r.URL.Path, "/test") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	words := []string{"test1", "test2", "test3", "test4"}
	// 50ms delay per request
	start := time.Now()
	findings := FuzzTargetService(ts.URL, words, "test", 2, 50)
	duration := time.Since(start)

	if len(findings) != 4 {
		t.Errorf("Tüm yollar bulunmalıydı, bulunan: %d", len(findings))
	}
	// 4 requests at ~50ms each should take at least ~100ms
	if duration < 100*time.Millisecond {
		t.Logf("Rate limit süresi: %v", duration)
	}
}

func TestSSHOpenSSHBanners(t *testing.T) {
	// 1. OpenSSH Banner
	raw1 := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
	spec1 := FindProbeSpecByPort(22)
	res1 := MatchBannerAgainstRules(spec1, raw1)
	if res1.ServiceName != "ssh" || res1.Version != "8.9p1" {
		t.Errorf("OpenSSH banner parse hatası: name=%s, ver=%s", res1.ServiceName, res1.Version)
	}
	if res1.Confidence < 90 {
		t.Errorf("OpenSSH confidence >= 90 olmalı, alinan: %d", res1.Confidence)
	}

	// 2. Dropbear SSH Banner
	raw2 := "SSH-2.0-Dropbear_2022.82"
	res2 := MatchBannerAgainstRules(spec1, raw2)
	if res2.ServiceName != "ssh" || res2.Version != "2022.82" {
		t.Errorf("Dropbear banner parse hatası: name=%s, ver=%s", res2.ServiceName, res2.Version)
	}
}

func TestFTPMultiLineBanners(t *testing.T) {
	raw := "220-Welcome to FTP Service\r\n220-vsftpd 3.0.5\r\n220 Ready"
	spec := FindProbeSpecByPort(21)
	res := MatchBannerAgainstRules(spec, raw)
	if res.ServiceName != "ftp" || res.Version != "3.0.5" {
		t.Errorf("FTP multi-line banner parse hatası: name=%s, ver=%s", res.ServiceName, res.Version)
	}
	if !strings.Contains(res.ServiceDesc, "vsftpd") {
		t.Errorf("FTP service desc 'vsftpd' içermeli: %s", res.ServiceDesc)
	}
}

func TestRedisINFOProbe(t *testing.T) {
	raw := "# Server\r\nredis_version:7.0.12\r\nredis_mode:standalone\r\nos:Linux"
	spec := FindProbeSpecByPort(6379)
	res := MatchBannerAgainstRules(spec, raw)
	if res.ServiceName != "redis" || res.Version != "7.0.12" {
		t.Errorf("Redis INFO parse hatası: name=%s, ver=%s", res.ServiceName, res.Version)
	}
	if res.Confidence < 90 {
		t.Errorf("Redis confidence >= 90 olmalı: %d", res.Confidence)
	}
}

func TestMemcachedVersionProbe(t *testing.T) {
	raw := "VERSION 1.6.18\r\n"
	spec := FindProbeSpecByPort(11211)
	res := MatchBannerAgainstRules(spec, raw)
	if res.ServiceName != "memcached" || res.Version != "1.6.18" {
		t.Errorf("Memcached VERSION parse hatası: name=%s, ver=%s", res.ServiceName, res.Version)
	}
}

func TestPostgreSQLProbing(t *testing.T) {
	// 1. SSLRequest 'S' response
	res1, handled1 := ParsePostgreSQLProbe(5432, []byte{'S'})
	if !handled1 || res1.ServiceName != "postgresql" {
		t.Errorf("PostgreSQL SSLRequest 'S' cevabı tanınamadı: handled=%v", handled1)
	}

	// 2. PostgreSQL Error Banner
	rawErr := "FATAL: password authentication failed for user (PostgreSQL 14.2)"
	res2, handled2 := ParsePostgreSQLProbe(5432, []byte(rawErr))
	if !handled2 || res2.ServiceName != "postgresql" || res2.Version != "14.2" {
		t.Errorf("PostgreSQL error banner versiyon çıkarılamadı: handled=%v, ver=%s", handled2, res2.Version)
	}
}

func TestRegexPriorityAndConfidence(t *testing.T) {
	// Apache should win over PHP or lower priority match
	raw := "Apache/2.4.41 (Ubuntu) PHP/8.0.2"
	sName, sDesc, sVer := ExtractVersionFromText(raw)
	if sName != "http" || !strings.Contains(sDesc, "Apache") || sVer != "2.4.41" {
		t.Errorf("Öncelikli Apache match seçilemedi: name=%s, desc=%s, ver=%s", sName, sDesc, sVer)
	}
}

func TestAnalyzeServiceSSHNoHTTP(t *testing.T) {
	// Mock SSH listener sending SSH banner immediately
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("TCP listener açılamadı: %v", err)
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"))
			}(conn)
		}
	}()

	portInfo := core.PortInfo{
		IP:          "127.0.0.1",
		Port:        port,
		Protocol:    "tcp",
		State:       "open",
		ServiceName: "ssh",
	}

	detail := AnalyzeService(portInfo, 2*time.Second)
	if detail.ServiceName != "ssh" {
		t.Errorf("Servis 'ssh' olmalı, alinan: %s", detail.ServiceName)
	}
	if detail.ServiceVersion != "8.9p1" {
		t.Errorf("Versiyon '8.9p1' olmalı, alinan: %s", detail.ServiceVersion)
	}
	if detail.VersionConfidence < 90 {
		t.Errorf("Confidence >= 90 olmalı, alinan: %d", detail.VersionConfidence)
	}
	if detail.VersionSource != "raw_banner" {
		t.Errorf("VersionSource 'raw_banner' olmalı, alinan: %s", detail.VersionSource)
	}
}

func TestSIPFalsePositiveBugFix(t *testing.T) {
	// Simulated Microsoft-HTTPAPI / WinRM / IIS HTTP 400 response
	httpBanner := "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=us-ascii\r\nServer: Microsoft-HTTPAPI/2.0\r\nDate: Thu, 27 Aug 2026 12:00:00 GMT\r\nConnection: close\r\nContent-Length: 311\r\n"
	
	spec80 := FindProbeSpecByPort(80)
	res80 := MatchBannerAgainstRules(spec80, httpBanner)
	if res80.ServiceName == "sip" {
		t.Fatalf("BUG REPRODUCED: Port 80 HTTP banner SIP olarak etiketlendi!")
	}

	spec5985 := FindProbeSpecByPort(5985)
	res5985 := MatchBannerAgainstRules(spec5985, httpBanner)
	if res5985.ServiceName == "sip" {
		t.Fatalf("BUG REPRODUCED: Port 5985 HTTP banner SIP olarak etiketlendi!")
	}
}

func TestSMB2NTLMSSPChallengeParsing(t *testing.T) {
	// Construct simulated NTLMSSP Type 2 Challenge packet:
	// NTLMSSP signature (8 bytes) + Type 2 (4 bytes)
	// TargetName descriptor (8 bytes: len=14, offset=56)
	// NegotiateFlags (4 bytes)
	// ServerChallenge (8 bytes)
	// Reserved (8 bytes)
	// TargetInfo descriptor (8 bytes: len=40, offset=70)
	// Version (8 bytes at offset 48): Major=10, Minor=0, Build=17763 (0x4563), NTLMRev=15
	
	pkt := make([]byte, 120)
	copy(pkt[0:], []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00}) // Signature
	pkt[8] = 0x02                                                  // Type 2 (Challenge)
	
	// TargetName descriptor (Offset 56, Len 14)
	binary.LittleEndian.PutUint16(pkt[12:14], 14)
	binary.LittleEndian.PutUint16(pkt[14:16], 14)
	binary.LittleEndian.PutUint32(pkt[16:20], 56)

	// TargetInfo descriptor (Offset 70, Len 40)
	binary.LittleEndian.PutUint16(pkt[40:42], 40)
	binary.LittleEndian.PutUint16(pkt[42:44], 40)
	binary.LittleEndian.PutUint32(pkt[44:48], 70)

	// OS Version struct at offset 48:
	pkt[48] = 10                                          // Major: 10
	pkt[49] = 0                                           // Minor: 0
	binary.LittleEndian.PutUint16(pkt[50:52], 17763)      // Build: 17763 (Windows Server 2019)
	pkt[55] = 15                                          // NTLM Revision: 15

	info, err := ParseNTLMSSPChallenge(pkt)
	if err != nil {
		t.Fatalf("ParseNTLMSSPChallenge hatası: %v", err)
	}
	if info.BuildNumber != 17763 {
		t.Errorf("Beklenen Build 17763, alinan %d", info.BuildNumber)
	}
	if !strings.Contains(info.OSName, "Windows Server 2019") {
		t.Errorf("Beklenen OSName 'Windows Server 2019', alinan '%s'", info.OSName)
	}
}

func TestLDAPRootDSEResponseParsing(t *testing.T) {
	// Construct simulated LDAP RootDSE response buffer
	mockLDAP := []byte("0\x81\x90\x02\x01\x01d\x81\x8a\x04\x000\x81\x85" +
		"0\x22\x04\x14defaultNamingContext1\x19\x04\x17DC=milsoft,DC=com,DC=tr" +
		"0\x23\x04\x0bdnsHostName1\x18\x04\x162012dc1.milsoft.com.tr" +
		"0\x24\x04\x1ddomainControllerFunctionality1\x03\x04\x017")

	info, err := ParseLDAPRootDSEResponse(mockLDAP)
	if err != nil {
		t.Fatalf("ParseLDAPRootDSEResponse hatası: %v", err)
	}
	if info.DefaultNamingContext != "DC=milsoft,DC=com,DC=tr" {
		t.Errorf("Beklenen DefaultNamingContext 'DC=milsoft,DC=com,DC=tr', alinan '%s'", info.DefaultNamingContext)
	}
	if info.DNSHostName != "2012dc1.milsoft.com.tr" {
		t.Errorf("Beklenen DNSHostName '2012dc1.milsoft.com.tr', alinan '%s'", info.DNSHostName)
	}
	if info.DomainControllerFunctionality != 7 {
		t.Errorf("Beklenen Functionality 7, alinan %d", info.DomainControllerFunctionality)
	}

	osDesc := FunctionalityLevelToWindowsOS(info.DomainControllerFunctionality)
	if !strings.Contains(osDesc, "Windows Server 2016") && !strings.Contains(osDesc, "2019") {
		t.Errorf("Beklenen OS 'Windows Server 2016 / 2019...', alinan '%s'", osDesc)
	}
}

func TestFaviconMMH3Hash(t *testing.T) {
	// Test Murmur3_32 standard properties
	emptyHash := CalculateFaviconMMH3([]byte{})
	if emptyHash != 0 {
		t.Errorf("Boş favicon hash 0 olmalı, alinan %d", emptyHash)
	}

	mockFavicon := []byte("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
	h := CalculateFaviconMMH3(mockFavicon)
	if h == 0 {
		t.Errorf("Favicon MMH3 hash hesaplanamadı")
	}

	// Verify known signature mapping
	if FaviconSignatures[116323821] != "springboot" {
		t.Errorf("Spring Boot favicon signature eşleşmedi")
	}
	if FaviconSignatures[81586312] != "jenkins" {
		t.Errorf("Jenkins favicon signature eşleşmedi")
	}
}

func TestMSRPCProbeParsing(t *testing.T) {
	// DCERPC Bind Ack: Version 5.0, PacketType 0x0c (Bind Ack)
	bindAck := []byte{0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00, 0x44, 0x00}
	res, ok := ParseMSRPCProbe(135, bindAck)
	if !ok || res.ServiceName != "msrpc" {
		t.Errorf("MSRPC Bind Ack tanınamadı: ok=%v, res=%+v", ok, res)
	}
	if !strings.Contains(res.ServiceDesc, "RPC Endpoint Mapper") {
		t.Errorf("MSRPC ServiceDesc hatalı: %s", res.ServiceDesc)
	}
}

func TestKerberosProbeParsing(t *testing.T) {
	// KRB-ERROR Application 30 (0x7e) containing realm
	krbError := []byte{0x7e, 0x30, 0x30, 0x2e, 0xa1, 0x03, 0x02, 0x01, 0x05}
	krbError = append(krbError, []byte("MILSOFT.COM.TR")...)
	
	res, ok := ParseKerberosProbe(88, krbError)
	if !ok || res.ServiceName != "kerberos" {
		t.Errorf("Kerberos error probe tanınamadı: ok=%v, res=%+v", ok, res)
	}
	if res.Version != "MILSOFT.COM.TR" {
		t.Errorf("Kerberos realm çıkarılamadı: realm=%s", res.Version)
	}
}

func TestCatchAllBaselineDetection(t *testing.T) {
	// Setup mock HTTP server that returns 301 (134 bytes) for any path except /real-secret-admin
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real-secret-admin" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><head><title>Admin Panel</title></head><body>Welcome Admin! Secret dashboard content here.</body></html>"))
			return
		}
		// Catch-All 301 redirection
		w.Header().Set("Location", "http://example.com/")
		w.WriteHeader(http.StatusMovedPermanently)
		_, _ = w.Write([]byte("<html><body>Moved permanently to root</body></html>")) // ~49 bytes
	}))
	defer server.Close()

	wordlist := []string{
		"env",
		"wp-config.php",
		"id_rsa",
		"actuator/env",
		"backup.sql",
		"non-existent-1",
		"non-existent-2",
		"real-secret-admin",
	}

	findings := FuzzTargetService(server.URL, wordlist, "test", 5, 0)

	// Catch-All filter must suppress all the non-existent 301s and only keep real-secret-admin!
	if len(findings) != 1 {
		t.Errorf("Beklenen sadece 1 gerçek bulgu (/real-secret-admin), alinan %d bulgu: %+v", len(findings), findings)
	}
	if len(findings) > 0 && findings[0].Path != "/real-secret-admin" {
		t.Errorf("Beklenen bulgu '/real-secret-admin', alinan: %s", findings[0].Path)
	}
}

func TestWAFDetectionAkamaiGHost(t *testing.T) {
	// Setup mock server simulating AkamaiGHost WAF 400 Bad Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AkamaiGHost")
		w.Header().Set("Mime-Version", "1.0")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("<HTML><HEAD><TITLE>Bad Request</TITLE></HEAD><BODY>400 Bad Request</BODY></HTML>"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	p, _ := strconv.Atoi(u.Port())
	res := ProbeHTTPService(u.Hostname(), p, false, 2*time.Second, u.Hostname())

	if !res.WAFDetected {
		t.Errorf("AkamaiGHost WAF tespit edilemedi!")
	}
	if !strings.Contains(res.WAFName, "Akamai") {
		t.Errorf("WAFName 'Akamai' içermeli, alinan: %s", res.WAFName)
	}
	if !strings.Contains(res.Title, "WAF Protected") {
		t.Errorf("WAF Title hatalı, alinan: %s", res.Title)
	}
}

func TestNmapXMLImport(t *testing.T) {
	mockXML := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -p 80,445 -oX - 192.168.1.100" start="1610000000" version="7.92">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <hostnames>
      <hostname name="server.corp.local" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.49" extrainfo="Ubuntu" conf="10"/>
        <script id="http-title" output="Internal Corporate Portal"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" product="Windows Server 2008" version="" conf="10"/>
        <script id="smb-vuln-ms17-010" output="State: VULNERABLE&#xa;Risk: Remote Code Execution (EternalBlue)"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	hosts, ports, services, nseFindings, err := ParseNmapXML([]byte(mockXML))
	if err != nil {
		t.Fatalf("ParseNmapXML hatası: %v", err)
	}

	if len(hosts) != 1 || hosts[0].IP != "192.168.1.100" || hosts[0].Hostname != "server.corp.local" {
		t.Errorf("Host parse hatası: %+v", hosts)
	}

	if len(ports) != 2 {
		t.Fatalf("2 açık port bekleniyordu, bulunan: %d", len(ports))
	}
	if ports[0].Source != "nmap" || !ports[0].Verified {
		t.Errorf("Port 0 metadata hatası: %+v", ports[0])
	}

	if len(services) != 2 {
		t.Fatalf("2 servis detayı bekleniyordu, bulunan: %d", len(services))
	}
	if !strings.Contains(services[0].ServiceDescription, "Apache") {
		t.Errorf("Servis 0 Apache bekleniyordu: %+v", services[0])
	}

	if len(nseFindings) != 2 {
		t.Fatalf("2 NSE bulgusu bekleniyordu, bulunan: %d", len(nseFindings))
	}
	var ms17Finding *core.NSEFinding
	for _, nf := range nseFindings {
		if nf.Script == "smb-vuln-ms17-010" {
			ms17Finding = &nf
			break
		}
	}
	if ms17Finding == nil {
		t.Fatalf("smb-vuln-ms17-010 NSE scripti bulunamadı!")
	}
	if ms17Finding.Severity != "CRITICAL" || ms17Finding.State != "VULNERABLE" {
		t.Errorf("NSE zafiyet derecelendirme hatası: %+v", ms17Finding)
	}
}

func TestMasscanJSONImport(t *testing.T) {
	// 1. JSON Array format
	mockJSON := `[
  { "ip": "10.0.0.50", "timestamp": "1610000000", "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] },
  { "ip": "10.0.0.50", "timestamp": "1610000000", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] },
  { "ip": "10.0.0.51", "timestamp": "1610000000", "ports": [ {"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }
]`

	hosts, ports, err := ParseMasscanJSON([]byte(mockJSON))
	if err != nil {
		t.Fatalf("ParseMasscanJSON (Array) hatası: %v", err)
	}
	if len(hosts) != 2 {
		t.Errorf("2 host bekleniyordu, alinan: %d", len(hosts))
	}
	if len(ports) != 3 {
		t.Errorf("3 port bekleniyordu, alinan: %d", len(ports))
	}
	if ports[0].Source != "masscan" || ports[0].Verified {
		t.Errorf("Masscan portu Source=masscan ve Verified=false olmalı: %+v", ports[0])
	}

	// 2. Text / Line format
	mockText := `
open tcp 80 192.168.1.1 1610000000
open tcp 443 192.168.1.1 1610000000
Discovered open port 22/tcp on 192.168.1.2
`
	hosts2, ports2, err2 := ParseMasscanJSON([]byte(mockText))
	if err2 != nil {
		t.Fatalf("ParseMasscanJSON (Text) hatası: %v", err2)
	}
	if len(hosts2) != 2 || len(ports2) != 3 {
		t.Errorf("Text formatı parse hatası: hosts=%d, ports=%d", len(hosts2), len(ports2))
	}
}

func TestPortVerifyHandshake(t *testing.T) {
	// Start a mock TCP listener for port verification
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Mock TCP listener baslatilamadi: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	openPortNum, _ := strconv.Atoi(portStr)

	testPorts := []core.PortInfo{
		{
			IP:       "127.0.0.1",
			Port:     openPortNum,
			Protocol: "tcp",
			Source:   "masscan",
			Verified: false,
		},
		{
			IP:       "127.0.0.1",
			Port:     59998, // Closed/unreachable port
			Protocol: "tcp",
			Source:   "masscan",
			Verified: false,
		},
	}

	verified, conflicts := VerifyPortsWithHandshake(testPorts, 5, 400*time.Millisecond)

	if len(verified) != 2 {
		t.Fatalf("Toplam 2 port dönmeliydi, alinan: %d", len(verified))
	}

	// Find the open port and closed port
	var openP, closedP *core.PortInfo
	for i := range verified {
		if verified[i].Port == openPortNum {
			openP = &verified[i]
		} else if verified[i].Port == 59998 {
			closedP = &verified[i]
		}
	}

	if openP == nil || !openP.Verified || openP.Conflict {
		t.Errorf("Açık port teyit edilemedi: %+v", openP)
	}

	if closedP == nil || closedP.Verified || !closedP.Conflict {
		t.Errorf("Kapalı port çelişki olarak işaretlenmedi: %+v", closedP)
	}

	if len(conflicts) != 1 || conflicts[0].Port != 59998 {
		t.Errorf("Çelişki listesi hatalı: %+v", conflicts)
	}
}

func TestNSEMappings(t *testing.T) {
	mappings := LoadNSEMappings("non-existent-config.yaml")
	if len(mappings) == 0 {
		t.Fatalf("Default NSE mappings bos döndü")
	}

	scripts445 := GetNSEScriptsForPortAndService(445, "microsoft-ds", mappings)
	if len(scripts445) == 0 || !strings.Contains(strings.Join(scripts445, ","), "ms17-010") {
		t.Errorf("Port 445 icin ms17-010 bekleniyordu: %+v", scripts445)
	}

	scriptsHTTP := GetNSEScriptsForPortAndService(8080, "http-proxy", mappings)
	if len(scriptsHTTP) == 0 || !strings.Contains(strings.Join(scriptsHTTP, ","), "http-vuln") {
		t.Errorf("HTTP servisi icin http zafiyet scriptleri bekleniyordu: %+v", scriptsHTTP)
	}
}

func TestDiscoverActiveDirectorySRVAndDNS(t *testing.T) {
	// Test Domain resolution helper
	findings := ResolveDomainDNS("localhost")
	if len(findings) == 0 {
		t.Logf("Localhost A kaydı çözümlenemedi (çevreye bağlı)")
	}

	// Test Reverse DNS helper on invalid IP (must handle gracefully)
	ptrFindings := ResolveReverseDNS([]string{"127.0.0.1", "invalid-ip", ""})
	if len(ptrFindings) == 0 {
		t.Logf("127.0.0.1 PTR çözümlenmedi veya boş döndü (normal)")
	}
}

func TestMSSQLTDSPreLoginProbe(t *testing.T) {
	// Setup mock TDS 7.x Pre-Login listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("TCP listener açılamadı: %v", err)
	}
	defer l.Close()

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if n >= 8 && buf[0] == 0x12 { // Pre-Login packet
			// Craft TDS Pre-Login Response (Option 0: Version 15.0.4188 -> Major 15, Minor 0, Build 4188 = 0x105c)
			resp := []byte{
				0x04, 0x01, 0x00, 0x1a, 0x00, 0x00, 0x01, 0x00, // Header: TDS Response (length 26)
				0x00, 0x00, 0x13, 0x00, 0x06, // Option 0: VERSION (Offset 19, Length 6)
				0x01, 0x00, 0x19, 0x00, 0x01, // Option 1: ENCRYPTION (Offset 25, Length 1)
				0xff,                         // Terminator
				0x0f, 0x00, 0x10, 0x5c, 0x00, 0x00, // Version (15.0.4188)
				0x00, // Encryption
			}
			_, _ = conn.Write(resp)
		}
	}()

	res, ok := ProbeMSSQLService("127.0.0.1", port, 2*time.Second)
	if !ok || res.ServiceName != "ms-sql-s" {
		t.Fatalf("MSSQL TDS Pre-Login probe başarısız: ok=%v, res=%+v", ok, res)
	}
	if res.Version != "15.0.4188" {
		t.Errorf("Beklenen versiyon 15.0.4188, alinan: %s", res.Version)
	}
	if !strings.Contains(res.ServiceDesc, "Microsoft SQL Server 2019") {
		t.Errorf("ServiceDesc 'Microsoft SQL Server 2019' içermeli: %s", res.ServiceDesc)
	}
}

func TestWinRMWSMANProbe(t *testing.T) {
	// Setup mock WinRM HTTP server responding to /wsman SOAP Identify
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wsman" && r.Method == "POST" {
			w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
			w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
<s:Body><wsmid:IdentifyResponse>
<wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>
<wsmid:ProductVersion>OS: 10.0.17763 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>
</wsmid:IdentifyResponse></s:Body></s:Envelope>`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	p, _ := strconv.Atoi(u.Port())

	res, ok := ProbeWinRMService(u.Hostname(), p, 2*time.Second)
	if !ok {
		t.Fatalf("WinRM WS-Management probe başarısız: ok=%v, res=%+v", ok, res)
	}
	if !strings.Contains(res.Version, "10.0.17763") {
		t.Errorf("WinRM OS versiyonu çıkarılamadı: %s", res.Version)
	}
	if !strings.Contains(res.ServiceDesc, "WinRM") {
		t.Errorf("ServiceDesc WinRM içermeli: %s", res.ServiceDesc)
	}
}

func TestHTTPMethodAuditAndRobotsDiscovery(t *testing.T) {
	// Setup mock HTTP server with OPTIONS and robots.txt
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("Allow", "GET, POST, OPTIONS, TRACE, PUT")
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin-portal/\nDisallow: /secret_config.php\nAllow: /public/\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()

	// 1. Audit HTTP Methods
	methods := AuditHTTPMethods(client, server.URL, "")
	if len(methods) != 5 {
		t.Errorf("5 metot bekleniyordu, bulunan: %d (%v)", len(methods), methods)
	}
	hasTrace := false
	hasPut := false
	for _, m := range methods {
		if m == "TRACE" {
			hasTrace = true
		}
		if m == "PUT" {
			hasPut = true
		}
	}
	if !hasTrace || !hasPut {
		t.Errorf("TRACE ve PUT metotları tespit edilemedi: %v", methods)
	}

	// 2. Fetch robots.txt paths
	robots := FetchRobotsTxtPaths(client, server.URL, "")
	if len(robots) < 2 {
		t.Errorf("En az 2 robots.txt yolu bulunmalıydı, bulunan: %d (%v)", len(robots), robots)
	}

	// 3. Dynamic extension variants
	baseWords := []string{"login", "admin"}
	aspnetMutated := GenerateTechnologyExtensionVariants(baseWords, "iis")
	hasAspx := false
	hasAxd := false
	for _, w := range aspnetMutated {
		if w == "login.aspx" {
			hasAspx = true
		}
		if w == "elmah.axd" {
			hasAxd = true
		}
	}
	if !hasAspx || !hasAxd {
		t.Errorf("ASP.NET / IIS dynamic mutations başarısız: %v", aspnetMutated)
	}
}

func TestSecretScanningAndDebugExposure(t *testing.T) {
	// 1. AWS Key and JWT leak test
	bodyWithAWS := "window.config = { 'apiKey': 'AKIAIOSFODNN7EXAMPLE', 'jwt': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' };"
	leaks := ScanBodyForSecrets(bodyWithAWS)
	if len(leaks) < 2 {
		t.Errorf("AWS Key ve JWT sızıntısı yakalanamadı: %v", leaks)
	}

	// 2. RSA Private Key leak test
	bodyWithKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y...\n-----END RSA PRIVATE KEY-----"
	keyLeaks := ScanBodyForSecrets(bodyWithKey)
	if len(keyLeaks) == 0 || keyLeaks[0] != "Private RSA/SSH Key" {
		t.Errorf("Private Key sızıntısı yakalanamadı: %v", keyLeaks)
	}

	// 3. Database credentials leak test
	bodyWithDB := "DATABASE_URL=postgres://postgres:SuperSecretP@ss123@db.prod.internal:5432/appdb"
	dbLeaks := ScanBodyForSecrets(bodyWithDB)
	if len(dbLeaks) == 0 || dbLeaks[0] != "Database Credentials" {
		t.Errorf("Database connection string sızıntısı yakalanamadı: %v", dbLeaks)
	}

	// 4. Debug Mode Exposure Tests
	springDebug := CheckDebugModeExposure("<html><body><h1>Whitelabel Error Page</h1><p>timestamp: 2026-08-28</p></body></html>")
	if !strings.Contains(springDebug, "Spring Boot") {
		t.Errorf("Spring Boot debug tespiti başarısız: %s", springDebug)
	}

	djangoDebug := CheckDebugModeExposure("Traceback (most recent call last): File django/core/handlers/exception.py, line 55, in inner")
	if !strings.Contains(djangoDebug, "Django") {
		t.Errorf("Django debug tespiti başarısız: %s", djangoDebug)
	}
}

func TestSubdomainTakeoverFingerprints(t *testing.T) {
	serviceGithub := CheckSubdomainTakeover("mycorp-docs.github.io")
	if serviceGithub != "GitHub Pages" {
		t.Errorf("GitHub Pages takeover fingerprint eşleşmedi: %s", serviceGithub)
	}

	serviceS3 := CheckSubdomainTakeover("assets.s3.amazonaws.com")
	if serviceS3 != "AWS S3 Bucket" {
		t.Errorf("AWS S3 takeover fingerprint eşleşmedi: %s", serviceS3)
	}

	serviceNone := CheckSubdomainTakeover("internal.corp.local")
	if serviceNone != "" {
		t.Errorf("Geçersiz takeover tespiti: %s", serviceNone)
	}
}

func TestCatchAll302DynamicQueryAnd401Detection(t *testing.T) {
	// 1. Test 302 Redirect Catch-All server with dynamic ReturnUrl
	server302 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dest := fmt.Sprintf("/Login.aspx?ReturnUrl=%s", url.QueryEscape(r.URL.Path))
		w.Header().Set("Location", dest)
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte("<html><body>Object moved to login</body></html>"))
	}))
	defer server302.Close()

	client := &http.Client{
		Transport: server302.Client().Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	baseline302 := DetectBaselineResponse(client, server302.URL, "")
	if !baseline302.IsCatchAll || baseline302.StatusCode != 302 {
		t.Errorf("302 Dynamic Catch-All tespit edilemedi: %+v", baseline302)
	}

	// Fuzzing a sensitive file like cmd.aspx on 302 catch-all server must be suppressed
	statusFilter := map[int]bool{200: true, 301: true, 302: true, 401: true, 403: true}
	resSensitive := FuzzSingleURL(client, server302.URL, "cmd.aspx", "test", statusFilter, nil, baseline302, "", nil)
	if resSensitive != nil {
		t.Errorf("302 Catch-All üzerindeki cmd.aspx sahte bulgu olarak basılmamalıydı: %+v", resSensitive)
	}

	// 2. Test 401 Unauthorized Catch-All server
	server401 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Access Denied"))
	}))
	defer server401.Close()

	client401 := &http.Client{
		Transport: server401.Client().Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	baseline401 := DetectBaselineResponse(client401, server401.URL, "")
	if !baseline401.IsCatchAll || baseline401.StatusCode != 401 {
		t.Errorf("401 Catch-All tespit edilemedi: %+v", baseline401)
	}

	res401 := FuzzSingleURL(client401, server401.URL, "admin", "test", statusFilter, nil, baseline401, "", nil)
	if res401 != nil {
		t.Errorf("401 Catch-All üzerindeki admin yolu filtrelenmeliydi: %+v", res401)
	}
}

func TestCatchAll200Soft404And500Baseline(t *testing.T) {
	// 1. Soft-404 returning 200 OK with identical body for all paths
	server200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real-secret.txt" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("REAL_SECRET_CONTENT_12345"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Custom Error Page</title></head><body>Page Not Found Custom Soft 404</body></html>"))
	}))
	defer server200.Close()

	client200 := &http.Client{
		Transport: server200.Client().Transport,
	}

	baseline200 := DetectBaselineResponse(client200, server200.URL, "")
	if !baseline200.IsCatchAll || baseline200.StatusCode != 200 {
		t.Errorf("200 Soft-404 Catch-All tespit edilemedi: %+v", baseline200)
	}

	wordlist := []string{"admin", "login", "config.php", "test", "real-secret.txt"}
	findings := FuzzTargetService(server200.URL, wordlist, "test", 2, 0)

	// Only /real-secret.txt should pass through, soft-404s must be filtered!
	if len(findings) != 1 || findings[0].Path != "/real-secret.txt" {
		t.Errorf("Soft-404 200 filtrelenemedi: bulunan sayi=%d, bulgular=%+v", len(findings), findings)
	}

	// 2. 500 Internal Server Error Baseline
	server500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error - Generic Exception"))
	}))
	defer server500.Close()

	client500 := &http.Client{
		Transport: server500.Client().Transport,
	}

	baseline500 := DetectBaselineResponse(client500, server500.URL, "")
	if !baseline500.IsCatchAll || baseline500.StatusCode != 500 {
		t.Errorf("500 Catch-All tespit edilemedi: %+v", baseline500)
	}
}

func TestCatchAllRealScanScenarioFalsePositivePrevention(t *testing.T) {
	// Simulating the exact 10.0.0.88:443 real-world bug:
	// 200+ words returning 302 with dynamic ReturnUrl
	serverRealWorld := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dest := fmt.Sprintf("/auth/login.aspx?ReturnUrl=%s", url.QueryEscape(r.URL.Path))
		w.Header().Set("Location", dest)
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte(fmt.Sprintf("<html><body>Object moved <a href=\"%s\">here</a></body></html>", dest)))
	}))
	defer serverRealWorld.Close()

	words := []string{
		"aspxshell.aspx", "zehir.aspx", "web.config", "wp-config.php",
		"admin", "login", "api", "backup.sql", "id_rsa", "config",
		"secret", ".env", "test", "appsettings.json",
	}

	findings := FuzzTargetService(serverRealWorld.URL, words, "test", 4, 0)
	// All should be suppressed as wildcard 302, zero false positives!
	if len(findings) != 0 {
		t.Errorf("302 Wildcard üzerinde sahte bulgular sızdı (sayi: %d): %+v", len(findings), findings)
	}
}

func TestTCPProbeUnifiedAndSync(t *testing.T) {
	// 1. Open port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("TCP listener açılamadı: %v", err)
	}
	defer ln.Close()

	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	openPort, _ := strconv.Atoi(pStr)

	lat, isOpen, err := TCPProbe("127.0.0.1", openPort, 1*time.Second)
	if !isOpen || lat == nil || err != nil {
		t.Errorf("TCPProbe açık portu tespit edemedi: isOpen=%v, lat=%v, err=%v", isOpen, lat, err)
	}

	// AsyncTCPPing wrapper
	latPing, isPingOpen := AsyncTCPPing("127.0.0.1", openPort, 1*time.Second)
	if !isPingOpen || latPing == nil {
		t.Errorf("AsyncTCPPing açık portu tespit edemedi: isOpen=%v, lat=%v", isPingOpen, latPing)
	}

	// 2. Closed port (RST)
	latClosed, isClosedOpen, _ := TCPProbe("127.0.0.1", 59997, 300*time.Millisecond)
	if isClosedOpen {
		t.Errorf("Kapalı port açık döndü!")
	}
	// On localhost, connection refused should yield a fast latency
	if latClosed != nil {
		t.Logf("RST Alındı (host alive, port closed): %.2fms", *latClosed)
	}
}

func TestScanMultipleHostsGentleRetry(t *testing.T) {
	// Mock TCP listener on port 80 equivalent
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listener hatası: %v", err)
	}
	defer ln.Close()

	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	openPort, _ := strconv.Atoi(pStr)

	// Scan with port list containing the open port
	ports, errScan := ScanMultipleHosts([]string{"127.0.0.1"}, []int{openPort, 59996}, 10, 500*time.Millisecond, "")
	if errScan != nil {
		t.Fatalf("ScanMultipleHosts hatası: %v", errScan)
	}
	if len(ports) != 1 || ports[0].Port != openPort {
		t.Errorf("Açık port bulunamadı: %+v", ports)
	}
}

func TestAuditSSHZeroServices(t *testing.T) {
	// Passing empty services list should return nil and no errors
	findings, err := AuditSSHMultiple(nil, 1*time.Second, "")
	if err != nil || len(findings) != 0 {
		t.Errorf("Boş servis listesi için 0 bulgu bekleniyordu, alinan: %v, err: %v", len(findings), err)
	}
}

func TestKerberosASREQProbe(t *testing.T) {
	// 1. KRB-ERROR response (0x7e) with realm RECON.LOCAL
	mockKrbError := []byte{
		0x7e, 0x40, // KRB-ERROR ASN.1 Application 30
		0x30, 0x3e,
		0xa1, 0x03, 0x02, 0x01, 0x05,
		0xa2, 0x03, 0x02, 0x01, 0x1e, // msg-type: KRB-ERROR (30)
		0xa4, 0x11, 0x1b, 0x0f, 'C', 'O', 'R', 'P', '.', 'E', 'X', 'A', 'M', 'P', 'L', 'E', '.', 'C', 'O',
		0xa5, 0x13, 0x30, 0x11, 0xa0, 0x03, 0x02, 0x01, 0x01,
	}

	res, ok := ParseKerberosProbe(88, mockKrbError)
	if !ok {
		t.Fatalf("ParseKerberosProbe başarısız!")
	}
	if res.ServiceName != "kerberos" {
		t.Errorf("Beklenen ServiceName 'kerberos', alinan '%s'", res.ServiceName)
	}
	if !strings.Contains(res.Banner, "CORP.EXAMPLE.CO") {
		t.Errorf("Beklenen Realm 'CORP.EXAMPLE.CO', alinan banner: '%s'", res.Banner)
	}

	// 2. KRB-ERROR with LDAP DN format DC=LAB,DC=LOCAL
	mockDNKrb := []byte("~\x30\x30\x2e\xa0\x03\x02\x01\x05DC=LAB,DC=LOCAL\x00\x00")
	resDN, okDN := ParseKerberosProbe(88, mockDNKrb)
	if !okDN {
		t.Fatalf("ParseKerberosProbe DN formatı başarısız!")
	}
	if resDN.Version != "LAB.LOCAL" {
		t.Errorf("Beklenen Version 'LAB.LOCAL', alinan '%s'", resDN.Version)
	}
}

func TestWinRMSOAPIdentifyParsing(t *testing.T) {
	mockSOAPResp := `HTTP/1.1 200 OK
Content-Type: application/soap+xml;charset=UTF-8
Server: Microsoft-HTTPAPI/2.0
Date: Mon, 31 Aug 2026 10:00:00 GMT
Connection: close
Content-Length: 450

<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Header/>
  <s:Body>
    <wsmid:IdentifyResponse>
      <wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>
      <wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>
      <wsmid:ProductVersion>OS: 10.0.17763 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>
    </wsmid:IdentifyResponse>
  </s:Body>
</s:Envelope>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
		_, _ = w.Write([]byte(mockSOAPResp))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())

	res, ok := ProbeWinRMService("127.0.0.1", port, 2*time.Second)
	if !ok {
		t.Fatalf("ProbeWinRMService başarısız!")
	}
	if !strings.Contains(res.ServiceDesc, "Windows Server 2019") {
		t.Errorf("Beklenen ServiceDesc 'Windows Server 2019', alinan '%s'", res.ServiceDesc)
	}
	if !strings.Contains(res.Banner, "Microsoft Corporation") {
		t.Errorf("Beklenen ProductVendor 'Microsoft Corporation', alinan banner '%s'", res.Banner)
	}
}

func TestExchangeWordlistSelection(t *testing.T) {
	svc := core.ServiceDetail{
		IP:                 "10.0.0.88",
		Port:               443,
		ServiceName:        "https",
		ServiceDescription: "Microsoft Exchange OWA",
		HTTPTitle:          "Outlook Web App - Sign In",
		HTTPTechnologies:   []string{"Exchange", "IIS"},
	}

	wordlists, tag := SelectWordlistForService(svc, nil, "wordlists/common.txt")
	if len(wordlists) == 0 {
		t.Fatalf("Wordlist seçilemedi!")
	}
	if !strings.Contains(tag, "exchange") {
		t.Errorf("Beklenen tag 'exchange', alinan '%s'", tag)
	}
	if !strings.Contains(wordlists[0], "exchange") {
		t.Errorf("Beklenen wordlist 'exchange.txt', alinan '%s'", wordlists[0])
	}
}

func TestIISCriticalPaths(t *testing.T) {
	words := []string{"index.html", "about.html"}
	expanded := GenerateTechnologyExtensionVariants(words, "iis")

	expectedEndpoints := []string{
		"elmah.axd",
		"web.config",
		"Global.asax",
		"_layouts/15/",
		"Telerik.Web.UI.WebResource.axd",
		"api/",
		"web.config.bak",
	}

	foundMap := make(map[string]bool)
	for _, w := range expanded {
		foundMap[w] = true
	}

	for _, ep := range expectedEndpoints {
		if !foundMap[ep] {
			t.Errorf("IIS kritik endpoint eksik: '%s'", ep)
		}
	}
}

func TestCatchAllMD5BodyHashFiltering(t *testing.T) {
	// Server returns 403 Forbidden with exact same body for all nonexistent URLs
	const wildcardBody = "<html><body>403 Forbidden - Access Denied Custom Error</body></html>"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/secret-admin-console" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>Welcome Administrator</body></html>"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(wildcardBody))
	}))
	defer server.Close()

	words := []string{"foo", "bar", "baz", "test1234", "secret-admin-console"}
	findings := FuzzTargetService(server.URL, words, "test", 4, 0)

	if len(findings) != 1 {
		t.Fatalf("Beklenen 1 bulgu (/secret-admin-console), alinan %d: %+v", len(findings), findings)
	}
	if findings[0].Path != "/secret-admin-console" {
		t.Errorf("Beklenen /secret-admin-console, alinan '%s'", findings[0].Path)
	}
}

func TestRobotsTxtBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /hidden-admin/\nDisallow: /internal-api\n"))
			return
		}
		if r.URL.Path == "/hidden-admin" || r.URL.Path == "/hidden-admin/" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Special Admin Forbidden Page"))
			return
		}
		if r.URL.Path == "/internal-api" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Internal API Documentation"))
			return
		}
		// Catch-all 302
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer server.Close()

	findings := FuzzTargetService(server.URL, []string{"nonexistent1", "nonexistent2"}, "test", 4, 0)

	foundPaths := make(map[string]bool)
	for _, f := range findings {
		foundPaths[f.Path] = true
	}

	if !foundPaths["/hidden-admin"] && !foundPaths["/hidden-admin/"] {
		t.Errorf("robots.txt /hidden-admin yolu yakalanamadı: %+v", findings)
	}
	if !foundPaths["/internal-api"] {
		t.Errorf("robots.txt /internal-api yolu yakalanamadı: %+v", findings)
	}
}



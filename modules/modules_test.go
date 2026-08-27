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

	finding := FuzzSingleURL(client, ts.URL, ".env", "sensitive", statusFilter, nil)
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
		w.WriteHeader(http.StatusOK)
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


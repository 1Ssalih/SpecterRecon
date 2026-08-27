package modules

import (
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


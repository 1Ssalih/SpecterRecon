package modules

import (
	"os"
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
		"apache":    "../wordlists/apache.txt",
		"jenkins":   "../wordlists/jenkins.txt",
		"wordpress": "../wordlists/wordpress.txt",
		"default":   "../wordlists/common.txt",
	}

	apacheSvc := core.ServiceDetail{
		ServiceName:        "http",
		ServiceDescription: "Apache HTTP Server 2.4.49",
	}
	wPath, key := SelectWordlistForService(apacheSvc, wordlistMap, "../wordlists/common.txt")
	if key != "apache" || !strings.Contains(wPath, "apache.txt") {
		t.Errorf("Apache servisi icin apache.txt secilmeli, alinan: key=%s, path=%s", key, wPath)
	}

	unknownSvc := core.ServiceDetail{
		ServiceName:        "http",
		ServiceDescription: "Unknown Custom Server",
	}
	wPath2, key2 := SelectWordlistForService(unknownSvc, wordlistMap, "../wordlists/common.txt")
	if key2 != "default" && key2 != "common" {
		t.Errorf("Bilinmeyen servis varsayilana dusmeli, alinan: key=%s, path=%s", key2, wPath2)
	}

	// Hem apache hem wordpress iceren servis: priority sirasina gore wordpress kazanmali
	wpApacheSvc := core.ServiceDetail{
		ServiceName:        "http",
		ServiceDescription: "WordPress on Apache",
		HTTPServer:         "Apache/2.4.49",
	}
	wPath3, key3 := SelectWordlistForService(wpApacheSvc, wordlistMap, "../wordlists/common.txt")
	if key3 != "wordpress" || !strings.Contains(wPath3, "wordpress.txt") {
		t.Errorf("WordPress+Apache servisinde wordpress.txt oncelikli olmali, alinan: key=%s, path=%s", key3, wPath3)
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

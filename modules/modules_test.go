package modules

import (
	"os"
	"strings"
	"testing"

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

func TestMatchOfflineCVEs(t *testing.T) {
	svc := core.ServiceDetail{
		IP:                 "127.0.0.1",
		Port:               80,
		ServiceName:        "http",
		ServiceDescription: "Apache HTTP Server",
		ServiceVersion:     "2.4.49",
	}
	vulns := MatchOfflineCVEs(svc)
	found := false
	for _, v := range vulns {
		if v.CVEID == "CVE-2021-41773" {
			found = true
			if v.Severity != "HIGH" || v.CVSSScore != 7.5 {
				t.Errorf("CVE-2021-41773 bilgileri hatali: %v", v)
			}
		}
	}
	if !found {
		t.Errorf("CVE-2021-41773 tespit edilemedi")
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
	vuln := core.VulnerabilityInfo{
		CVEID:           "CVE-2021-41773",
		CVSSScore:       7.5,
		Severity:        "HIGH",
		Description:     "Path traversal",
		AffectedService: "http (127.0.0.1:80)",
	}
	finding := core.DirFuzzFinding{
		URL:             "http://127.0.0.1:80/admin",
		Path:            "/admin",
		StatusCode:      200,
		WordlistMatched: "apache",
	}

	report := BuildCompleteReport("test.local", []core.DNSFinding{dns}, []core.HostInfo{host}, []core.PortInfo{port}, []core.ServiceDetail{svc}, []core.VulnerabilityInfo{vuln}, []core.DirFuzzFinding{finding}, 1.25)
	outPath, err := GenerateHTMLReport(report, "../templates/report.html.tmpl", "output/test/test_report.html")
	if err != nil {
		t.Fatalf("GenerateHTMLReport hatasi: %v", err)
	}

	bytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("Rapor okunamadi: %v", err)
	}
	content := string(bytes)
	if !strings.Contains(content, "test.local") || !strings.Contains(content, "CVE-2021-41773") || !strings.Contains(content, "/admin") {
		t.Errorf("Rapor icerigi eksik: %s", content)
	}
}

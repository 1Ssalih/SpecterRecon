package modules

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

var Top20Ports = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}

var Top100Ports = []int{
	20, 21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161,
	179, 389, 443, 445, 465, 500, 514, 515, 520, 587, 591, 631, 636, 873, 902, 989, 990, 993,
	995, 1025, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2181,
	2222, 2375, 2376, 3000, 3128, 3306, 3389, 3690, 4000, 4443, 5000, 5432, 5672, 5900, 5985,
	5986, 6000, 6379, 7001, 7077, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9092,
	9200, 9300, 9418, 9999, 10000, 11211, 27017, 27018, 50000,
}

var CommonServiceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 81: "http-alt",
	88: "kerberos", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios-ssn",
	143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
	636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1521: "oracle",
	2049: "nfs", 2222: "ssh-alt", 2375: "docker", 2376: "docker-ssl", 3000: "http-dev",
	3306: "mysql", 3389: "ms-wbt-server", 5000: "http-dev", 5432: "postgresql", 5672: "amqp",
	5900: "vnc", 5985: "wsman", 6379: "redis", 7001: "weblogic", 8000: "http-alt",
	8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
	9090: "prometheus", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

// ParsePortSpecs parses port string specifications into a sorted slice of ports.
func ParsePortSpecs(spec string) []int {
	spec = strings.ToLower(strings.TrimSpace(spec))
	if spec == "" || spec == "top-100" || spec == "default" || spec == "common" {
		res := make([]int, len(Top100Ports))
		copy(res, Top100Ports)
		sort.Ints(res)
		return res
	}
	if spec == "top-20" {
		res := make([]int, len(Top20Ports))
		copy(res, Top20Ports)
		sort.Ints(res)
		return res
	}
	if spec == "top-1000" || spec == "all-common" {
		portSet := make(map[int]bool)
		for i := 1; i <= 1024; i++ {
			portSet[i] = true
		}
		for _, p := range Top100Ports {
			portSet[p] = true
		}
		extra := []int{1433, 1521, 2082, 2083, 2087, 3000, 3306, 3389, 5000, 5432, 6379, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 27017}
		for _, p := range extra {
			portSet[p] = true
		}
		var res []int
		for p := range portSet {
			res = append(res, p)
		}
		sort.Ints(res)
		return res
	}
	if spec == "full" || spec == "all" || spec == "1-65535" {
		res := make([]int, 65535)
		for i := 1; i <= 65535; i++ {
			res[i-1] = i
		}
		return res
	}

	portMap := make(map[int]bool)
	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err1 == nil && err2 == nil && start <= end {
					for i := start; i <= end; i++ {
						if i >= 1 && i <= 65535 {
							portMap[i] = true
						}
					}
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil && p >= 1 && p <= 65535 {
				portMap[p] = true
			}
		}
	}

	var res []int
	for p := range portMap {
		res = append(res, p)
	}
	sort.Ints(res)
	if len(res) == 0 {
		return Top100Ports
	}
	return res
}

// ScanSinglePort attempts a TCP connect to a single target:port.
func ScanSinglePort(ip string, port int, timeout time.Duration) *core.PortInfo {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	_ = conn.Close()

	latency := float64(time.Since(start).Nanoseconds()) / 1e6
	service := CommonServiceNames[port]
	if service == "" {
		service = "unknown"
	}

	return &core.PortInfo{
		IP:             ip,
		Port:           port,
		Protocol:       "tcp",
		State:          "open",
		ServiceName:    service,
		ResponseTimeMs: &latency,
	}
}

// ScanTargetPorts scans a list of ports on a target IP using Goroutines.
func ScanTargetPorts(ip string, ports []int, concurrency int, timeout time.Duration, outputFile string) ([]core.PortInfo, error) {
	core.LogInfo("Port Taraması başlatılıyor: Hedef='%s', Port Sayısı=%d, Eşzamanlılık=%d", ip, len(ports), concurrency)
	core.LogAudit("PORT_SCAN_START", ip, fmt.Sprintf("ports=%d, timeout=%v", len(ports), timeout), "SUCCESS")

	if concurrency <= 0 {
		concurrency = 100
	}
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	portChan := make(chan int, len(ports))
	for _, p := range ports {
		portChan <- p
	}
	close(portChan)

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		openPorts []core.PortInfo
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				res := ScanSinglePort(ip, port, timeout)
				if res != nil {
					mu.Lock()
					openPorts = append(openPorts, *res)
					mu.Unlock()
					core.LogSuccess("Açık Port Bulundu: %s:%d (%s) [%.2fms]", ip, res.Port, res.ServiceName, *res.ResponseTimeMs)
				}
			}
		}()
	}

	wg.Wait()

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	if outputFile != "" {
		_ = core.SavePorts(openPorts, outputFile)
	}

	core.LogInfo("Port Taraması tamamlandı: %d açık port tespit edildi (%s).", len(openPorts), outputFile)
	core.LogAudit("PORT_SCAN_COMPLETE", ip, fmt.Sprintf("open_ports=%d", len(openPorts)), "SUCCESS")

	return openPorts, nil
}

// ScanMultipleHosts scans open ports across multiple host IPs.
func ScanMultipleHosts(ips []string, ports []int, concurrency int, timeout time.Duration, outputFile string) ([]core.PortInfo, error) {
	var allPorts []core.PortInfo
	for _, ip := range ips {
		found, err := ScanTargetPorts(ip, ports, concurrency, timeout, "")
		if err == nil {
			allPorts = append(allPorts, found...)
		}
	}
	if outputFile != "" {
		_ = core.SavePorts(allPorts, outputFile)
	}
	return allPorts, nil
}

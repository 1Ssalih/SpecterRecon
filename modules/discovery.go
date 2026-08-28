package modules

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

// ParseTargets parses CIDR, range, single IP, or hostname into a slice of IP strings.
func ParseTargets(target string) []string {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}

	// Check if hostname (no CIDR, no range, not numeric IP)
	if !strings.Contains(target, "/") && !strings.Contains(target, "-") {
		if net.ParseIP(target) == nil {
			ips, err := net.LookupIP(target)
			if err == nil && len(ips) > 0 {
				var res []string
				for _, ip := range ips {
					if ipv4 := ip.To4(); ipv4 != nil {
						res = append(res, ipv4.String())
					}
				}
				if len(res) > 0 {
					return res
				}
			}
			return []string{target}
		}
		return []string{target}
	}

	// Range (e.g. 192.168.1.1-192.168.1.50 or 192.168.1.1-50)
	if strings.Contains(target, "-") {
		parts := strings.Split(target, "-")
		if len(parts) == 2 {
			startIPStr := strings.TrimSpace(parts[0])
			endPart := strings.TrimSpace(parts[1])

			startIP := net.ParseIP(startIPStr).To4()
			if startIP != nil {
				var endIP net.IP
				if strings.Contains(endPart, ".") {
					endIP = net.ParseIP(endPart).To4()
				} else {
					// e.g. 1-50
					ipParts := strings.Split(startIPStr, ".")
					prefix := strings.Join(ipParts[:3], ".")
					endIP = net.ParseIP(fmt.Sprintf("%s.%s", prefix, endPart)).To4()
				}

				if endIP != nil {
					startInt := ipToUint32(startIP)
					endInt := ipToUint32(endIP)
					if startInt <= endInt {
						var res []string
						for i := startInt; i <= endInt; i++ {
							res = append(res, uint32ToIP(i).String())
						}
						return res
					}
				}
			}
		}
	}

	// CIDR (e.g. 192.168.1.0/24)
	ip, ipnet, err := net.ParseCIDR(target)
	if err == nil {
		var res []string
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			res = append(res, ip.String())
		}
		// Filter network and broadcast address if network has >2 addresses
		if len(res) > 2 {
			return res[1 : len(res)-1]
		}
		return res
	}

	return []string{target}
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// GetSystemARPTable reads the OS ARP table.
func GetSystemARPTable() map[string]string {
	arpMap := make(map[string]string)
	cmd := exec.Command("arp", "-a")
	out, err := cmd.Output()
	if err != nil {
		return arpMap
	}

	lines := strings.Split(string(out), "\n")
	reWindows := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})`)
	reUnix := regexp.MustCompile(`\(?(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F:]{17})`)

	for _, line := range lines {
		if runtime.GOOS == "windows" {
			matches := reWindows.FindStringSubmatch(line)
			if len(matches) > 2 {
				mac := strings.ToLower(strings.ReplaceAll(matches[2], "-", ":"))
				arpMap[matches[1]] = mac
			}
		} else {
			matches := reUnix.FindStringSubmatch(line)
			if len(matches) > 2 {
				arpMap[matches[1]] = strings.ToLower(matches[2])
			}
		}
	}
	return arpMap
}

// SystemICMPPing sends a system ping packet.
func SystemICMPPing(ip string, timeout time.Duration) *float64 {
	start := time.Now()
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		timeoutMs := int(timeout.Milliseconds())
		cmd = exec.Command("ping", "-n", "1", "-w", strconv.Itoa(timeoutMs), ip)
	} else if runtime.GOOS == "darwin" {
		timeoutSec := int(timeout.Seconds())
		if timeoutSec < 1 {
			timeoutSec = 1
		}
		cmd = exec.Command("ping", "-c", "1", "-t", strconv.Itoa(timeoutSec), ip)
	} else {
		timeoutSec := int(timeout.Seconds())
		if timeoutSec < 1 {
			timeoutSec = 1
		}
		cmd = exec.Command("ping", "-c", "1", "-W", strconv.Itoa(timeoutSec), ip)
	}

	out, err := cmd.CombinedOutput()
	if err == nil {
		outUpper := bytes.ToUpper(out)
		if bytes.Contains(outUpper, []byte("TTL=")) || bytes.Contains(outUpper, []byte("BYTES FROM")) {
			lat := float64(time.Since(start).Nanoseconds()) / 1e6
			return &lat
		}
	}
	return nil
}

// AsyncTCPPing tests if a host is alive by connecting to a common port.
// Returns latency and whether the port was actually open (true) or actively refused via RST (false).
func AsyncTCPPing(ip string, port int, timeout time.Duration) (*float64, bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		// If connection was refused actively (RST), host is definitely alive!
		if strings.Contains(err.Error(), "refused") {
			lat := float64(time.Since(start).Nanoseconds()) / 1e6
			return &lat, false
		}
		return nil, false
	}
	_ = conn.Close()
	lat := float64(time.Since(start).Nanoseconds()) / 1e6
	return &lat, true
}

// ProbeSingleHost probes a host via ICMP and common TCP ports.
func ProbeSingleHost(ip string, commonPorts []int, timeout time.Duration, arpMap map[string]string) *core.HostInfo {
	// 1. ICMP Ping check
	lat := SystemICMPPing(ip, timeout)
	if lat != nil {
		mac := arpMap[ip]
		host := core.NewHostInfo(ip, "icmp")
		host.MAC = mac
		host.LatencyMs = lat
		return &host
	}

	// 2. TCP Ping check across common ports
	for _, port := range commonPorts {
		tcpLat, isOpen := AsyncTCPPing(ip, port, 1000*time.Millisecond)
		if tcpLat != nil {
			mac := arpMap[ip]
			method := fmt.Sprintf("tcp_open:%d", port)
			if !isOpen {
				method = fmt.Sprintf("tcp_rst:%d", port)
			}
			host := core.NewHostInfo(ip, method)
			host.MAC = mac
			host.LatencyMs = tcpLat
			return &host
		}
	}

	return nil
}

// DiscoverHosts scans and identifies all responsive hosts in the target scope.
func DiscoverHosts(target string, commonPorts []int, timeout time.Duration, concurrency int, outputFile string) ([]core.HostInfo, error) {
	core.LogInfo("Host Discovery başlatılıyor: Hedef='%s'", target)
	core.LogAudit("HOST_DISCOVERY_START", target, fmt.Sprintf("timeout=%v, concurrency=%d", timeout, concurrency), "SUCCESS")

	if len(commonPorts) == 0 {
		commonPorts = []int{80, 443, 22, 445, 8080, 3389, 21, 23, 25, 53}
	}
	if concurrency <= 0 {
		concurrency = 50
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	ipList := ParseTargets(target)
	core.LogInfo("Taranacak toplam hedef IP adresi sayısı: %d", len(ipList))

	arpMap := GetSystemARPTable()

	ipChan := make(chan string, len(ipList))
	for _, ip := range ipList {
		ipChan <- ip
	}
	close(ipChan)

	var (
		wg             sync.WaitGroup
		mu             sync.Mutex
		discoveredHost []core.HostInfo
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				h := ProbeSingleHost(ip, commonPorts, timeout, arpMap)
				if h != nil {
					mu.Lock()
					discoveredHost = append(discoveredHost, *h)
					mu.Unlock()
					latStr := "N/A"
					if h.LatencyMs != nil {
						latStr = fmt.Sprintf("%.2fms", *h.LatencyMs)
					}
					core.LogSuccess("Canlı Host Bulundu: %s ➔ %s (%s, %s)", h.IP, h.State, h.DiscoveryMethod, latStr)
				}
			}
		}()
	}

	wg.Wait()

	sort.Slice(discoveredHost, func(i, j int) bool {
		ip1 := net.ParseIP(discoveredHost[i].IP).To4()
		ip2 := net.ParseIP(discoveredHost[j].IP).To4()
		if ip1 != nil && ip2 != nil {
			return ipToUint32(ip1) < ipToUint32(ip2)
		}
		return discoveredHost[i].IP < discoveredHost[j].IP
	})

	if outputFile != "" {
		_ = core.SaveHosts(discoveredHost, outputFile)
		core.LogInfo("Host Discovery tamamlandı: %d canlı host kaydedildi (%s).", len(discoveredHost), outputFile)
	} else {
		core.LogInfo("Host Discovery tamamlandı: %d canlı host tespit edildi.", len(discoveredHost))
	}
	core.LogAudit("HOST_DISCOVERY_COMPLETE", target, fmt.Sprintf("found_hosts=%d", len(discoveredHost)), "SUCCESS")

	return discoveredHost, nil
}

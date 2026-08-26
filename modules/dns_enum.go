package modules

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

// IsDomainName determines whether a given target string is a hostname/domain rather than an IP/CIDR/range.
func IsDomainName(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	// CIDR or Range
	if strings.Contains(target, "/") || strings.Contains(target, "-") {
		return false
	}
	// Direct IPv4 or IPv6
	if net.ParseIP(target) != nil {
		return false
	}
	// Domain name usually contains letters and valid characters
	return true
}

// ResolveDomainDNS performs standard A, AAAA and CNAME resolution for a domain.
func ResolveDomainDNS(domain string) []core.DNSFinding {
	domain = strings.TrimSpace(domain)
	var findings []core.DNSFinding
	seen := make(map[string]bool)

	// A and AAAA records
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	var r net.Resolver
	ips, err := r.LookupIP(ctx, "ip", domain)
	if err == nil {
		for _, ip := range ips {
			recType := "A"
			if ip.To4() == nil {
				recType = "AAAA"
			}
			key := fmt.Sprintf("%s:%s", domain, ip.String())
			if !seen[key] {
				seen[key] = true
				findings = append(findings, core.DNSFinding{
					Hostname:   domain,
					IP:         ip.String(),
					RecordType: recType,
					Source:     "root_resolution",
				})
			}
		}
	}

	return findings
}

// BruteForceSubdomains checks candidate subdomains concurrently using Goroutines.
func BruteForceSubdomains(domain string, wordlist []string, concurrency int, timeout time.Duration) []core.DNSFinding {
	if concurrency <= 0 {
		concurrency = 30
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	wordChan := make(chan string, len(wordlist))
	for _, w := range wordlist {
		wordChan <- strings.TrimSpace(w)
	}
	close(wordChan)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		findings []core.DNSFinding
		seen     = make(map[string]bool)
	)

	var resolver net.Resolver

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range wordChan {
				if sub == "" {
					continue
				}
				fqdn := fmt.Sprintf("%s.%s", sub, domain)
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				ips, err := resolver.LookupIP(ctx, "ip4", fqdn)
				cancel()

				if err == nil && len(ips) > 0 {
					for _, ip := range ips {
						ipStr := ip.String()
						mu.Lock()
						key := fmt.Sprintf("%s:%s", fqdn, ipStr)
						if !seen[key] {
							seen[key] = true
							finding := core.DNSFinding{
								Hostname:   fqdn,
								IP:         ipStr,
								RecordType: "A",
								Source:     "subdomain_bruteforce",
							}
							findings = append(findings, finding)
							core.LogSuccess("Subdomain Bulundu: %s ➔ %s", fqdn, ipStr)
						}
						mu.Unlock()
					}
				}
			}
		}()
	}

	wg.Wait()

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Hostname < findings[j].Hostname
	})

	return findings
}

// EnumerateDNS runs root DNS resolution and optional subdomain brute-forcing.
func EnumerateDNS(target string, runSubdomains bool, subdomainsWordlist string, concurrency int, outputFile string) ([]core.DNSFinding, []string, error) {
	core.LogInfo("Modül 0: DNS Enumeration başlatılıyor: Hedef Alan Adı='%s'", target)
	core.LogAudit("DNS_ENUM_START", target, fmt.Sprintf("subdomains=%v, concurrency=%d", runSubdomains, concurrency), "SUCCESS")

	// 1. Root Domain Resolution
	rootFindings := ResolveDomainDNS(target)
	var allFindings []core.DNSFinding
	allFindings = append(allFindings, rootFindings...)

	for _, f := range rootFindings {
		core.LogSuccess("DNS Kaydı Çözümlendi: %s (%s) ➔ %s", f.Hostname, f.RecordType, f.IP)
	}

	// 2. Subdomain Brute-Force (if enabled)
	if runSubdomains {
		if subdomainsWordlist == "" {
			subdomainsWordlist = "wordlists/subdomains.txt"
		}
		words := LoadWordlist(subdomainsWordlist)
		if len(words) > 0 {
			core.LogInfo("Subdomain Brute-force yürütülüyor (%d aday kelime)...", len(words))
			subFindings := BruteForceSubdomains(target, words, concurrency, 2*time.Second)
			allFindings = append(allFindings, subFindings...)
		} else {
			core.LogWarning("Subdomain wordlist bulunamadı veya boş: %s", subdomainsWordlist)
		}
	}

	if outputFile == "" {
		outputFile = "output/ip_list.json"
	}

	if err := core.SaveIPList(allFindings, outputFile); err != nil {
		core.LogWarning("ip_list.json kaydedilemedi: %v", err)
	} else {
		core.LogInfo("DNS sonuçları kaydedildi: %d kayıt (%s)", len(allFindings), outputFile)
	}

	// Collect unique IPs to feed downstream discovery & scanning
	ipMap := make(map[string]bool)
	var uniqueIPs []string
	for _, f := range allFindings {
		if !ipMap[f.IP] {
			ipMap[f.IP] = true
			uniqueIPs = append(uniqueIPs, f.IP)
		}
	}

	core.LogAudit("DNS_ENUM_COMPLETE", target, fmt.Sprintf("total_records=%d, unique_ips=%d", len(allFindings), len(uniqueIPs)), "SUCCESS")

	return allFindings, uniqueIPs, nil
}

package modules

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/wordlists"
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

// ResolveDomainDNS performs comprehensive A, AAAA, CNAME, MX, NS, and TXT record resolution for a domain.
func ResolveDomainDNS(domain string) []core.DNSFinding {
	domain = strings.TrimSpace(domain)
	var findings []core.DNSFinding
	seen := make(map[string]bool)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var r net.Resolver

	// 1. A and AAAA records (prefer IPv4 first for stable routing)
	ips, err := r.LookupIP(ctx, "ip4", domain)
	if err == nil && len(ips) > 0 {
		for _, ip := range ips {
			key := fmt.Sprintf("%s:%s:A", domain, ip.String())
			if !seen[key] {
				seen[key] = true
				findings = append(findings, core.DNSFinding{
					Hostname:   domain,
					IP:         ip.String(),
					RecordType: "A",
					Source:     "root_resolution",
				})
			}
		}
	} else {
		ips, err = r.LookupIP(ctx, "ip", domain)
		if err == nil {
			for _, ip := range ips {
				recType := "A"
				if ip.To4() == nil {
					recType = "AAAA"
				}
				key := fmt.Sprintf("%s:%s:%s", domain, ip.String(), recType)
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
	}

	// 2. CNAME Record
	if cname, err := r.LookupCNAME(ctx, domain); err == nil && cname != "" && strings.TrimSuffix(cname, ".") != domain {
		cnameClean := strings.TrimSuffix(cname, ".")
		key := fmt.Sprintf("%s:%s:CNAME", domain, cnameClean)
		if !seen[key] {
			seen[key] = true
			findings = append(findings, core.DNSFinding{
				Hostname:   domain,
				RecordType: "CNAME",
				Value:      cnameClean,
				Source:     "root_resolution",
			})
		}
	}

	// 3. MX Records (Mail Exchangers)
	if mxRecords, err := r.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxRecords {
			mxHost := strings.TrimSuffix(mx.Host, ".")
			key := fmt.Sprintf("%s:%s:MX", domain, mxHost)
			if !seen[key] {
				seen[key] = true
				// Resolve MX host to IP
				mxIP := ""
				if mxIPs, err := r.LookupIP(ctx, "ip4", mxHost); err == nil && len(mxIPs) > 0 {
					mxIP = mxIPs[0].String()
				}
				findings = append(findings, core.DNSFinding{
					Hostname:   mxHost,
					IP:         mxIP,
					RecordType: "MX",
					Value:      fmt.Sprintf("Pref:%d -> %s", mx.Pref, mxHost),
					Source:     "root_resolution",
				})
			}
		}
	}

	// 4. NS Records (Name Servers)
	if nsRecords, err := r.LookupNS(ctx, domain); err == nil {
		for _, ns := range nsRecords {
			nsHost := strings.TrimSuffix(ns.Host, ".")
			key := fmt.Sprintf("%s:%s:NS", domain, nsHost)
			if !seen[key] {
				seen[key] = true
				nsIP := ""
				if nsIPs, err := r.LookupIP(ctx, "ip4", nsHost); err == nil && len(nsIPs) > 0 {
					nsIP = nsIPs[0].String()
				}
				findings = append(findings, core.DNSFinding{
					Hostname:   nsHost,
					IP:         nsIP,
					RecordType: "NS",
					Value:      nsHost,
					Source:     "root_resolution",
				})
			}
		}
	}

	// 5. TXT Records (SPF, DMARC, Domain Validations)
	if txtRecords, err := r.LookupTXT(ctx, domain); err == nil {
		for _, txt := range txtRecords {
			trimmedTxt := strings.TrimSpace(txt)
			if trimmedTxt == "" {
				continue
			}
			key := fmt.Sprintf("%s:%s:TXT", domain, trimmedTxt)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, core.DNSFinding{
					Hostname:   domain,
					RecordType: "TXT",
					Value:      trimmedTxt,
					Source:     "root_resolution",
				})
			}
		}
	}

	return findings
}

// DiscoverActiveDirectorySRV probes well-known Active Directory and Enterprise SRV records to reveal Domain Controllers, Kerberos KDC, and Global Catalog servers.
func DiscoverActiveDirectorySRV(domain string) []core.DNSFinding {
	srvQueries := []struct {
		service string
		proto   string
		name    string
		desc    string
	}{
		{"ldap", "tcp", domain, "Active Directory LDAP DC"},
		{"kerberos", "tcp", domain, "Kerberos KDC"},
		{"kpasswd", "tcp", domain, "Kerberos Password Server"},
		{"gc", "tcp", domain, "Active Directory Global Catalog"},
		{"ldap", "tcp", "dc._msdcs." + domain, "AD DC Domain Controller (MSDCS)"},
		{"kerberos", "tcp", "dc._msdcs." + domain, "AD Kerberos KDC (MSDCS)"},
		{"autodiscover", "tcp", domain, "Exchange Autodiscover"},
		{"sip", "tls", domain, "SIP over TLS"},
		{"xmpp-server", "tcp", domain, "XMPP Server"},
	}

	var (
		findings []core.DNSFinding
		seen     = make(map[string]bool)
		r        net.Resolver
	)

	for _, sq := range srvQueries {
		ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		_, srvs, err := r.LookupSRV(ctx, sq.service, sq.proto, sq.name)
		cancel()

		if err == nil && len(srvs) > 0 {
			for _, srv := range srvs {
				targetHost := strings.TrimSuffix(srv.Target, ".")
				key := fmt.Sprintf("%s:%s:%d", sq.service, targetHost, srv.Port)
				if !seen[key] {
					seen[key] = true
					// Resolve target host IP
					targetIP := ""
					subCtx, subCancel := context.WithTimeout(context.Background(), 2*time.Second)
					if ipList, err := r.LookupIP(subCtx, "ip4", targetHost); err == nil && len(ipList) > 0 {
						targetIP = ipList[0].String()
					}
					subCancel()

					srvFinding := core.DNSFinding{
						Hostname:   targetHost,
						IP:         targetIP,
						RecordType: "SRV",
						Value:      fmt.Sprintf("_%s._%s.%s ➔ %s:%d (%s)", sq.service, sq.proto, sq.name, targetHost, srv.Port, sq.desc),
						Source:     "srv_discovery",
					}
					findings = append(findings, srvFinding)
					core.LogSuccess("AD/Enterprise SRV Keşfedildi: _%s._%s.%s ➔ %s:%d [%s] (%s)",
						sq.service, sq.proto, sq.name, targetHost, srv.Port, targetIP, sq.desc)
				}
			}
		}
	}

	return findings
}

// ResolveReverseDNS performs PTR lookups on discovered IP addresses.
func ResolveReverseDNS(ips []string) []core.DNSFinding {
	var (
		findings []core.DNSFinding
		seen     = make(map[string]bool)
		r        net.Resolver
	)

	for _, ip := range ips {
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		names, err := r.LookupAddr(ctx, ip)
		cancel()

		if err == nil && len(names) > 0 {
			for _, name := range names {
				cleanName := strings.TrimSuffix(name, ".")
				key := fmt.Sprintf("%s:%s:PTR", ip, cleanName)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, core.DNSFinding{
						Hostname:   cleanName,
						IP:         ip,
						RecordType: "PTR",
						Value:      cleanName,
						Source:     "reverse_ptr",
					})
					core.LogSuccess("Ters DNS (PTR) Çözümlendi: %s ➔ %s", ip, cleanName)
				}
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
		resolver net.Resolver
	)

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

// Known Subdomain Takeover fingerprints (CNAME suffix -> Service name)
var TakeoverFingerprints = map[string]string{
	"github.io":              "GitHub Pages",
	"herokuapp.com":          "Heroku",
	"herokudns.com":          "Heroku DNS",
	"s3.amazonaws.com":       "AWS S3 Bucket",
	"s3-website":             "AWS S3 Website",
	"azurewebsites.net":      "Azure App Service",
	"cloudapp.net":           "Azure CloudApp",
	"trafficmanager.net":     "Azure Traffic Manager",
	"cloudfront.net":         "AWS CloudFront",
	"ghost.io":               "Ghost",
	"surge.sh":               "Surge.sh",
	"myshopify.com":          "Shopify",
	"bitbucket.io":           "Bitbucket",
	"pantheonsite.io":        "Pantheon",
	"readme.io":              "Readme.io",
	"zendesk.com":            "Zendesk",
	"helpjuice.com":          "Helpjuice",
	"helpscoutdocs.com":      "HelpScout",
	"worksites.net":          "Worksites",
	"wpengine.com":           "WPEngine",
	"flywheelstaging.com":    "Flywheel",
	"firebaseapp.com":        "Firebase",
	"webflow.io":             "Webflow",
	"cname.vercel-dns.com":   "Vercel",
	"netlify.app":            "Netlify",
}

// CheckSubdomainTakeover checks if a CNAME target matches known takeover candidates.
func CheckSubdomainTakeover(cname string) string {
	cnameLower := strings.ToLower(cname)
	for suffix, service := range TakeoverFingerprints {
		if strings.Contains(cnameLower, suffix) {
			return service
		}
	}
	return ""
}

// DetectWildcardDNS checks if a domain has wildcard DNS records (*.domain.com) by probing a random non-existent subdomain.
func DetectWildcardDNS(domain string) (bool, string) {
	randomSub := fmt.Sprintf("specter-recon-rnd-%d.%s", time.Now().UnixNano()%1000000, domain)
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	var r net.Resolver
	ips, err := r.LookupIP(ctx, "ip4", randomSub)
	if err == nil && len(ips) > 0 {
		return true, ips[0].String()
	}
	return false, ""
}

// TestZoneTransferAXFR tests whether a given Name Server allows AXFR (DNS Zone Transfer) for the target domain.
func TestZoneTransferAXFR(domain, nsServer string) ([]core.DNSFinding, error) {
	nsHost := nsServer
	if !strings.Contains(nsHost, ":") {
		nsHost = net.JoinHostPort(nsHost, "53")
	}

	conn, err := net.DialTimeout("tcp", nsHost, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	// Build raw DNS AXFR query over TCP (2 bytes length prefix + DNS header + QNAME + QTYPE=AXFR=252 + QCLASS=IN=1)
	var qnameBuf []byte
	parts := strings.Split(strings.Trim(domain, "."), ".")
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		qnameBuf = append(qnameBuf, byte(len(p)))
		qnameBuf = append(qnameBuf, []byte(p)...)
	}
	qnameBuf = append(qnameBuf, 0) // null terminator

	dnsQuery := []byte{
		0x13, 0x37, // Transaction ID
		0x00, 0x00, // Flags: Standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
	}
	dnsQuery = append(dnsQuery, qnameBuf...)
	dnsQuery = append(dnsQuery, 0x00, 0xFC) // QTYPE: AXFR (252)
	dnsQuery = append(dnsQuery, 0x00, 0x01) // QCLASS: IN (1)

	// Prepend 2-byte TCP message length prefix
	msgLen := uint16(len(dnsQuery))
	tcpPacket := append([]byte{byte(msgLen >> 8), byte(msgLen & 0xFF)}, dnsQuery...)

	if _, err := conn.Write(tcpPacket); err != nil {
		return nil, err
	}

	// Read 2-byte length
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	respLen := (int(lenBuf[0]) << 8) | int(lenBuf[1])
	if respLen < 12 || respLen > 65535 {
		return nil, fmt.Errorf("invalid DNS response length: %d", respLen)
	}

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, err
	}

	// Check RCODE (low 4 bits of byte 3)
	rcode := respBuf[3] & 0x0F
	ancount := (int(respBuf[6]) << 8) | int(respBuf[7])

	if rcode == 0 && ancount > 0 {
		core.LogWarning("🚨 KRİTİK GÜVENLİK AÇIĞI: DNS Zone Transfer (AXFR) AÇIK! NS: %s, Hedef: %s (Kayıt Sayısı: %d)", nsServer, domain, ancount)
		return []core.DNSFinding{
			{
				Hostname:   domain,
				RecordType: "AXFR",
				Value:      fmt.Sprintf("VULNERABLE: Zone Transfer allowed by %s (%d records returned)", nsServer, ancount),
				Source:     "axfr_leak",
			},
		}, nil
	}

	return nil, fmt.Errorf("zone transfer refused (rcode=%d)", rcode)
}

// EnumerateDNS orchestrates root DNS resolution, Active Directory SRV discovery, Subdomain brute-forcing, and Reverse PTR resolution.
func EnumerateDNS(target string, runSubdomains bool, subdomainsWordlist string, concurrency int, outputFile string) ([]core.DNSFinding, []string, error) {
	core.LogInfo("Modül 0: Kapsamlı DNS & Altyapı Keşfi başlatılıyor: Hedef='%s'", target)
	core.LogAudit("DNS_ENUM_START", target, fmt.Sprintf("subdomains=%v, concurrency=%d", runSubdomains, concurrency), "SUCCESS")

	var allFindings []core.DNSFinding

	// 1. Root Domain Resolution (A, AAAA, CNAME, MX, NS, TXT)
	rootFindings := ResolveDomainDNS(target)
	allFindings = append(allFindings, rootFindings...)

	var nsServers []string
	for _, f := range rootFindings {
		if f.RecordType == "NS" && f.Hostname != "" {
			nsServers = append(nsServers, f.Hostname)
			if f.IP != "" {
				nsServers = append(nsServers, f.IP)
			}
		}
		if f.RecordType == "CNAME" {
			if service := CheckSubdomainTakeover(f.Value); service != "" {
				core.LogWarning("⚠️ Olası Subdomain Takeover Riski: %s ➔ %s (Servis: %s)", f.Hostname, f.Value, service)
			}
		}
		if f.Value != "" {
			core.LogSuccess("DNS Kaydı (%s): %s ➔ %s", f.RecordType, f.Hostname, f.Value)
		} else if f.IP != "" {
			core.LogSuccess("DNS Kaydı (%s): %s ➔ %s", f.RecordType, f.Hostname, f.IP)
		}
	}

	// 2. Test AXFR Zone Transfer against all discovered Name Servers
	if len(nsServers) > 0 {
		seenNS := make(map[string]bool)
		for _, ns := range nsServers {
			if !seenNS[ns] && ns != "" {
				seenNS[ns] = true
				if axfrFindings, err := TestZoneTransferAXFR(target, ns); err == nil && len(axfrFindings) > 0 {
					allFindings = append(allFindings, axfrFindings...)
				}
			}
		}
	}

	// 3. Active Directory & Enterprise SRV Discovery
	srvFindings := DiscoverActiveDirectorySRV(target)
	allFindings = append(allFindings, srvFindings...)

	// 4. Wildcard DNS Detection & Subdomain Brute-Force (if enabled)
	if runSubdomains {
		hasWildcard, wildcardIP := DetectWildcardDNS(target)
		if hasWildcard {
			core.LogWarning("Wildcard DNS Tespit Edildi: *.%s ➔ %s (Sahte subdomainler filtrelenecektir)", target, wildcardIP)
		}

		if subdomainsWordlist == "" {
			subdomainsWordlist = "wordlists/subdomains.txt"
		}
		words := LoadWordlist(subdomainsWordlist)
		if len(words) == 0 {
			words = wordlists.ParseWordlistString(wordlists.SubdomainsTxt)
		}
		if len(words) > 0 {
			core.LogInfo("Subdomain Brute-force yürütülüyor (%d aday kelime)...", len(words))
			subFindings := BruteForceSubdomains(target, words, concurrency, 2*time.Second)
			
			// Filter out wildcard IP if wildcard is active
			for _, sf := range subFindings {
				if hasWildcard && sf.IP == wildcardIP {
					continue
				}
				allFindings = append(allFindings, sf)
			}
		} else {
			core.LogWarning("Subdomain wordlist bulunamadı veya boş: %s", subdomainsWordlist)
		}
	}

	// Collect unique IPs to feed downstream discovery & scanning
	ipMap := make(map[string]bool)
	var uniqueIPs []string
	for _, f := range allFindings {
		if f.IP != "" && net.ParseIP(f.IP) != nil && !ipMap[f.IP] {
			ipMap[f.IP] = true
			uniqueIPs = append(uniqueIPs, f.IP)
		}
	}

	// 5. Reverse DNS (PTR) Resolution on discovered unique IPs
	if len(uniqueIPs) > 0 {
		ptrFindings := ResolveReverseDNS(uniqueIPs)
		allFindings = append(allFindings, ptrFindings...)
	}

	if outputFile == "" {
		outputFile = "output/ip_list.json"
	}

	if err := core.SaveIPList(allFindings, outputFile); err != nil {
		core.LogWarning("ip_list.json kaydedilemedi: %v", err)
	} else {
		core.LogInfo("DNS sonuçları kaydedildi: %d kayıt (%s)", len(allFindings), outputFile)
	}

	core.LogAudit("DNS_ENUM_COMPLETE", target, fmt.Sprintf("total_records=%d, unique_ips=%d", len(allFindings), len(uniqueIPs)), "SUCCESS")

	return allFindings, uniqueIPs, nil
}

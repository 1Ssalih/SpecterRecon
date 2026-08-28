package modules

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/specter-recon/recon-tool/core"
)

// Nmap XML Data Structures according to standard nmap.dtd

type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Scanner string     `xml:"scanner,attr"`
	Version string     `xml:"version,attr"`
	Hosts   []NmapHost `xml:"host"`
}

type NmapHost struct {
	Status    NmapStatus     `xml:"status"`
	Addresses []NmapAddress  `xml:"address"`
	Hostnames []NmapHostname `xml:"hostnames>hostname"`
	Ports     []NmapPort     `xml:"ports>port"`
}

type NmapStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type NmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type NmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    NmapState   `xml:"state"`
	Service  NmapService `xml:"service"`
	Scripts  []NmapScript`xml:"script"`
}

type NmapState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type NmapService struct {
	Name       string `xml:"name,attr"`
	Product    string `xml:"product,attr"`
	Version    string `xml:"version,attr"`
	ExtraInfo  string `xml:"extrainfo,attr"`
	Confidence int    `xml:"conf,attr"`
	Method     string `xml:"method,attr"`
}

type NmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// ParseNmapXML parses Nmap XML bytes into SpecterRecon core models.
func ParseNmapXML(data []byte) ([]core.HostInfo, []core.PortInfo, []core.ServiceDetail, []core.NSEFinding, error) {
	var run NmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("nmap XML parse hatası: %w", err)
	}

	var (
		hosts       []core.HostInfo
		ports       []core.PortInfo
		services    []core.ServiceDetail
		nseFindings []core.NSEFinding
	)

	for _, h := range run.Hosts {
		if h.Status.State != "up" && h.Status.State != "" {
			continue
		}

		ip := ""
		for _, addr := range h.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" || ip == "" {
				ip = addr.Addr
			}
		}
		if ip == "" {
			continue
		}

		hostname := ""
		if len(h.Hostnames) > 0 {
			hostname = h.Hostnames[0].Name
		}

		hostInfo := core.NewHostInfo(ip, "nmap_xml")
		hostInfo.Hostname = hostname
		hosts = append(hosts, hostInfo)

		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}

			proto := strings.ToLower(p.Protocol)
			if proto == "" {
				proto = "tcp"
			}

			portInfo := core.PortInfo{
				IP:          ip,
				Hostname:    hostname,
				Port:        p.PortID,
				Protocol:    proto,
				State:       "open",
				ServiceName: p.Service.Name,
				Source:      "nmap",
				Verified:    true,
				Conflict:    false,
			}
			ports = append(ports, portInfo)

			// Construct ServiceDetail
			fullVer := strings.TrimSpace(fmt.Sprintf("%s %s %s", p.Service.Product, p.Service.Version, p.Service.ExtraInfo))
			fullVer = SanitizeBanner(fullVer)

			svcName := p.Service.Name
			if svcName == "" {
				svcName = "unknown"
			}

			conf := p.Service.Confidence * 10
			if conf == 0 {
				conf = 85
			}
			if conf > 100 {
				conf = 100
			}

			svcDetail := core.ServiceDetail{
				IP:                 ip,
				Hostname:           hostname,
				Port:               p.PortID,
				Protocol:           proto,
				ServiceName:        svcName,
				ServiceDescription: SanitizeBanner(p.Service.Product),
				ServiceVersion:     SanitizeBanner(p.Service.Version),
				BannerRaw:          fullVer,
				VersionSource:      "nmap_xml",
				VersionConfidence:  conf,
				ProbeUsed:          "nmap_service_scan",
				SSLEnabled:         strings.Contains(svcName, "ssl") || strings.Contains(svcName, "https") || p.PortID == 443 || p.PortID == 8443,
				State:              "open",
			}
			services = append(services, svcDetail)

			// Process NSE Script outputs
			for _, scr := range p.Scripts {
				out := strings.TrimSpace(scr.Output)
				if out == "" {
					continue
				}

				sev := "INFO"
				state := "INFO"
				outLower := strings.ToLower(out)

				if strings.Contains(outLower, "vulnerable") || strings.Contains(outLower, "state: vulnerable") || strings.Contains(outLower, "exploit") {
					sev = "HIGH"
					state = "VULNERABLE"
					if strings.Contains(outLower, "critical") || strings.Contains(outLower, "remote code execution") || strings.Contains(outLower, "ms17-010") {
						sev = "CRITICAL"
					}
				} else if strings.Contains(outLower, "likely vulnerable") {
					sev = "MEDIUM"
					state = "LIKELY_VULNERABLE"
				}

				nseFindings = append(nseFindings, core.NSEFinding{
					Host:     ip,
					Port:     p.PortID,
					Script:   scr.ID,
					Output:   out,
					Severity: sev,
					State:    state,
				})
			}
		}
	}

	return hosts, ports, services, nseFindings, nil
}

// LoadNmapXMLFile reads and parses an Nmap XML output file.
func LoadNmapXMLFile(filePath string) ([]core.HostInfo, []core.PortInfo, []core.ServiceDetail, []core.NSEFinding, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("nmap XML dosyası okunamadı (%s): %w", filePath, err)
	}
	return ParseNmapXML(data)
}

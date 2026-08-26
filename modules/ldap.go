package modules

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

// AuditLDAPService inspects LDAP / Active Directory servers for anonymous bind and naming context.
func AuditLDAPService(ip string, port int, timeout time.Duration) core.LdapFinding {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	finding := core.LdapFinding{
		IP:       ip,
		Port:     port,
		Severity: "INFO",
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return finding
	}
	defer conn.Close()

	// LDAP Anonymous Bind Request Packet (BER Encoded)
	// Message ID: 1, ProtocolOp: BindRequest (0x60), Version: 3, Name: "", Auth: Simple ("")
	ldapBindPkg := []byte{
		0x30, 0x0c, // Sequence header
		0x02, 0x01, 0x01, // Message ID: 1
		0x60, 0x07, // Bind Request (0x60)
		0x02, 0x01, 0x03, // LDAP Version: 3
		0x04, 0x00, // Simple Name: ""
		0x80, 0x00, // Simple Password: ""
	}

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(ldapBindPkg)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, errRead := conn.Read(buf)

	if errRead == nil && n > 8 {
		// LDAP Response Message (0x61 = BindResponse)
		// Result Code 0x0A (Offset): 0x00 = success (Anonymous Bind Accepted!)
		for i := 0; i < n-2; i++ {
			if buf[i] == 0x0a && buf[i+1] == 0x01 && buf[i+2] == 0x00 { // ResultCode: success
				finding.AnonymousBind = true
				finding.Severity = "HIGH"
				finding.Notes = append(finding.Notes, "ANONYMOUS LDAP BIND KABUL EDİLDİ! (Kimlik doğrulamasız dizin okuma riski)")
				break
			}
		}
	}

	// 2. Query Root DSE for Domain Name / Naming Context
	// LDAP SearchRequest for RootDSE (base="", scope=base, filter=(objectClass=*), attrs=["defaultNamingContext"])
	rootDseSearchPkg := []byte{
		0x30, 0x25,
		0x02, 0x01, 0x02, // Message ID: 2
		0x63, 0x20, // Search Request
		0x04, 0x00, // Base Object: ""
		0x0a, 0x01, 0x00, // Scope: base (0)
		0x0a, 0x01, 0x00, // DerefAliases: neverDeref (0)
		0x02, 0x01, 0x00, // SizeLimit: 0
		0x02, 0x01, 0x00, // TimeLimit: 0
		0x01, 0x01, 0x00, // TypesOnly: false
		0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, // Filter: present objectClass
		0x30, 0x00, // Attributes: all
	}

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(rootDseSearchPkg)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n2, errRead2 := conn.Read(buf)
	if errRead2 == nil && n2 > 20 {
		respStr := string(buf[:n2])
		if strings.Contains(respStr, "DC=") {
			finding.ServerType = "Active Directory"
			// Extract DC=domain,DC=com
			idx := strings.Index(respStr, "DC=")
			if idx != -1 {
				sub := respStr[idx:]
				endIdx := strings.IndexAny(sub, "\x00\r\n\x04")
				if endIdx != -1 {
					sub = sub[:endIdx]
				}
				finding.NamingContext = sub
				finding.DomainName = strings.ReplaceAll(strings.ReplaceAll(sub, "DC=", ""), ",", ".")
				finding.Notes = append(finding.Notes, fmt.Sprintf("Domain Tespit Edildi: %s", finding.DomainName))
			}
		}
	}

	return finding
}

// AuditLDAPMultiple scans all LDAP services across target hosts.
func AuditLDAPMultiple(services []core.ServiceDetail, timeout time.Duration, outputFile string) ([]core.LdapFinding, error) {
	var targets []core.ServiceDetail
	for _, s := range services {
		if s.ServiceName == "ldap" || s.ServiceName == "ldaps" || s.Port == 389 || s.Port == 636 || s.Port == 3268 {
			targets = append(targets, s)
		}
	}

	if len(targets) == 0 {
		return nil, nil
	}

	core.LogInfo("LDAP / Active Directory Denetimi (Anonymous Bind, Domain Naming) başlatılıyor (%d LDAP servisi)...", len(targets))
	var findings []core.LdapFinding

	for _, t := range targets {
		f := AuditLDAPService(t.IP, t.Port, timeout)
		if f.AnonymousBind || f.DomainName != "" {
			findings = append(findings, f)
			if f.AnonymousBind {
				core.LogWarning("🚨 CRITICAL LDAP ANONYMOUS BIND (%s:%d - %s)", f.IP, f.Port, f.DomainName)
			} else {
				core.LogInfo("LDAP Bilgisi (%s:%d): Domain=%s (%s)", f.IP, f.Port, f.DomainName, f.ServerType)
			}
		}
	}

	if outputFile != "" {
		_ = core.SaveLdapFindings(findings, outputFile)
	}

	return findings, nil
}

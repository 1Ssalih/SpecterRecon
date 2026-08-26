package modules

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

type IotFinding struct {
	IP       string   `json:"ip"`
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"` // Modbus, BACnet, RTSP, VNC
	Exposed  bool     `json:"exposed"`
	Severity string   `json:"severity"`
	Notes    []string `json:"notes,omitempty"`
}

// AuditIoTService tests industrial / IoT endpoints for exposure.
func AuditIoTService(ip string, port int, protocol string, timeout time.Duration) IotFinding {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	finding := IotFinding{
		IP:       ip,
		Port:     port,
		Protocol: protocol,
		Severity: "INFO",
	}

	switch {
	case port == 502 || protocol == "modbus":
		finding.Protocol = "Modbus TCP"
		auditModbus(addr, &finding, timeout)

	case port == 554 || protocol == "rtsp":
		finding.Protocol = "RTSP Camera"
		auditRTSP(addr, &finding, timeout)

	case port >= 5900 && port <= 5905 || protocol == "vnc":
		finding.Protocol = "VNC"
		auditVNC(addr, &finding, timeout)
	}

	return finding
}

func auditModbus(addr string, f *IotFinding, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	// Modbus Read Device Identification / Read Coils Request
	modbusReq := []byte{
		0x00, 0x01, // Transaction ID
		0x00, 0x00, // Protocol ID
		0x00, 0x06, // Length
		0x01,       // Unit ID
		0x01,       // Function Code: Read Coils
		0x00, 0x00, // Starting Address
		0x00, 0x01, // Quantity of Coils
	}

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(modbusReq)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, errRead := conn.Read(buf)

	if errRead == nil && n >= 9 {
		f.Exposed = true
		f.Severity = "CRITICAL"
		f.Notes = append(f.Notes, "MODBUS TCP ENDÜSTRİYEL CİHAZ (PLC/SCADA) AÇIKTA! (Kimlik doğrulama yok)")
	}
}

func auditRTSP(addr string, f *IotFinding, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("OPTIONS rtsp://" + addr + "/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"))

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	resp, errRead := reader.ReadString('\n')

	if errRead == nil && strings.Contains(resp, "RTSP/1.0 200") {
		f.Exposed = true
		f.Severity = "HIGH"
		f.Notes = append(f.Notes, "RTSP IP KAMERA VİDEO YAYINI AÇIKTA! (RTSP/1.0 200 OK)")
	}
}

func auditVNC(addr string, f *IotFinding, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	banner, errRead := reader.ReadString('\n')

	if errRead == nil && strings.HasPrefix(banner, "RFB ") {
		f.Exposed = true
		f.Notes = append(f.Notes, fmt.Sprintf("VNC Uzaktan Masaüstü Açık (Versiyon: %s)", strings.TrimSpace(banner)))

		// Send same version back
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write([]byte(banner))

		// Check Security Types
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, errSec := conn.Read(buf)

		if errSec == nil && n > 1 {
			// Security type 1 = None (No password required!)
			numTypes := int(buf[0])
			for i := 1; i <= numTypes && i < n; i++ {
				if buf[i] == 1 { // SecurityType None
					f.Severity = "CRITICAL"
					f.Notes = append(f.Notes, "VNC ŞİFRESİZ UZAKTAN MASAÜSTÜ ERİŞİMİ MÜMKÜN! (Security Type: None)")
					break
				}
			}
		}
	}
}

// AuditIoTMultiple scans target services for industrial / IoT protocol exposures.
func AuditIoTMultiple(services []core.ServiceDetail, timeout time.Duration, outputFile string) ([]IotFinding, error) {
	iotPorts := map[int]string{
		502:  "modbus",
		554:  "rtsp",
		5900: "vnc",
		5901: "vnc",
	}

	var targets []core.ServiceDetail
	for _, s := range services {
		if _, ok := iotPorts[s.Port]; ok || strings.Contains(s.ServiceName, "vnc") || strings.Contains(s.ServiceName, "modbus") || strings.Contains(s.ServiceName, "rtsp") {
			targets = append(targets, s)
		}
	}

	if len(targets) == 0 {
		return nil, nil
	}

	core.LogInfo("IoT / OT / Endüstriyel Cihaz Denetimi (Modbus, RTSP Kamera, VNC) başlatılıyor (%d servisi)...", len(targets))
	var findings []IotFinding

	for _, t := range targets {
		proto := t.ServiceName
		if mapped, ok := iotPorts[t.Port]; ok {
			proto = mapped
		}
		f := AuditIoTService(t.IP, t.Port, proto, timeout)
		if f.Exposed {
			findings = append(findings, f)
			core.LogWarning("🚨 CRITICAL IOT/OT EXPOSURE (%s:%d - %s): %s", f.IP, f.Port, f.Protocol, strings.Join(f.Notes, " | "))
		}
	}

	return findings, nil
}

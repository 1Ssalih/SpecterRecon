package modules

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
	"gopkg.in/yaml.v3"
)

// ConfigSchema represents partial config schema for nse_mappings loading.
type ConfigSchema struct {
	NSEMappings map[string][]string `yaml:"nse_mappings"`
}

// CheckToolAvailable checks if an executable exists in the system PATH.
func CheckToolAvailable(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// LoadNSEMappings loads mapped NSE scripts from config.yaml with sensible fallbacks.
func LoadNSEMappings(configPath string) map[string][]string {
	if configPath == "" {
		configPath = "config.yaml"
	}

	defaults := map[string][]string{
		"445":  {"smb-vuln-ms17-010", "smb-os-discovery"},
		"443":  {"ssl-heartbleed", "ssl-cert"},
		"80":   {"http-vuln-cve2021-41773", "http-methods"},
		"21":   {"ftp-anon"},
		"22":   {"ssh-auth-methods"},
		"3389": {"rdp-enum-encryption"},
		"http": {"http-vuln-cve2021-41773", "http-methods"},
		"smb":  {"smb-vuln-ms17-010"},
		"ssl":  {"ssl-heartbleed"},
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return defaults
	}

	var cfg ConfigSchema
	if err := yaml.Unmarshal(data, &cfg); err != nil || len(cfg.NSEMappings) == 0 {
		return defaults
	}

	return cfg.NSEMappings
}

// GetNSEScriptsForPortAndService finds applicable NSE scripts based on port number and service name.
func GetNSEScriptsForPortAndService(port int, serviceName string, mappings map[string][]string) []string {
	var scripts []string
	seen := make(map[string]bool)

	add := func(list []string) {
		for _, s := range list {
			if !seen[s] && s != "" {
				seen[s] = true
				scripts = append(scripts, s)
			}
		}
	}

	// 1. Port match
	portStr := strconv.Itoa(port)
	if list, ok := mappings[portStr]; ok {
		add(list)
	}

	// 2. Service name match
	sLower := strings.ToLower(serviceName)
	for key, list := range mappings {
		if strings.EqualFold(key, sLower) || (sLower != "" && strings.Contains(sLower, strings.ToLower(key))) {
			add(list)
		}
	}

	return scripts
}

// RunMasscanSubprocess executes Masscan as a subprocess and parses open ports.
func RunMasscanSubprocess(target string, portSpec string, rate int, timeout time.Duration) ([]core.HostInfo, []core.PortInfo, error) {
	if !CheckToolAvailable("masscan") {
		return nil, nil, fmt.Errorf("masscan sistemde bulunamadı (PATH içinde yok)")
	}

	if portSpec == "" {
		portSpec = "1-65535"
	}
	if rate <= 0 {
		rate = 10000
	}
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}

	tempOut := filepath.Join(os.TempDir(), fmt.Sprintf("specter_masscan_%d.json", time.Now().UnixNano()))
	defer os.Remove(tempOut)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{
		target,
		"-p" + portSpec,
		fmt.Sprintf("--rate=%d", rate),
		"-oJ", tempOut,
	}

	core.LogInfo("Masscan Süreci Başlatılıyor: masscan %s", strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, "masscan", args...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start).Seconds()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, nil, fmt.Errorf("masscan taraması zaman aşımına uğradı (timeout: %v)", timeout)
	}

	if err != nil {
		errStr := stderrBuf.String()
		if strings.Contains(strings.ToLower(errStr), "permission") || strings.Contains(strings.ToLower(errStr), "raw socket") || strings.Contains(strings.ToLower(errStr), "pcap") {
			core.LogError("Masscan Yetki Hatası (Root / Capability Eksikliği):")
			core.LogWarning("Linux üzerinde çalıştırmak için şu komutu verin: sudo setcap cap_net_raw,cap_net_admin=eip specter-recon")
			core.LogWarning("Veya root olarak çalıştırın: sudo specter-recon ...")
		}
		return nil, nil, fmt.Errorf("masscan çalıştırma hatası: %w (stderr: %s)", err, strings.TrimSpace(errStr))
	}

	hosts, ports, parseErr := LoadMasscanJSONFile(tempOut)
	if parseErr != nil {
		return nil, nil, fmt.Errorf("masscan çıktısı okunamadı: %w", parseErr)
	}

	core.LogAudit("MASSCAN_COMPLETE", target, fmt.Sprintf("hosts=%d, open_ports=%d, duration=%.2fs", len(hosts), len(ports), duration), "SUCCESS")
	core.LogSuccess("Masscan tamamlandı: %d açık port tespit edildi (%.2f sn).", len(ports), duration)

	return hosts, ports, nil
}

// RunNmapNSESubprocess executes Nmap with target NSE scripts against specific ports.
func RunNmapNSESubprocess(target string, ports []int, scripts []string, timeout time.Duration) ([]core.NSEFinding, error) {
	if !CheckToolAvailable("nmap") {
		return nil, fmt.Errorf("nmap sistemde bulunamadı (PATH içinde yok)")
	}
	if len(ports) == 0 || len(scripts) == 0 {
		return nil, nil
	}

	if timeout <= 0 {
		timeout = 3 * time.Minute
	}

	var portStrs []string
	for _, p := range ports {
		portStrs = append(portStrs, strconv.Itoa(p))
	}
	portArg := strings.Join(portStrs, ",")
	scriptArg := strings.Join(scripts, ",")

	tempOut := filepath.Join(os.TempDir(), fmt.Sprintf("specter_nmap_%d.xml", time.Now().UnixNano()))
	defer os.Remove(tempOut)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{
		"-sV",
		"--script=" + scriptArg,
		"-p" + portArg,
		"-oX", tempOut,
		target,
	}

	core.LogInfo("Nmap NSE Zafiyet Taraması Başlatılıyor: nmap %s", strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, "nmap", args...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start).Seconds()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("nmap NSE taraması zaman aşımına uğradı (timeout: %v)", timeout)
	}

	if err != nil {
		return nil, fmt.Errorf("nmap çalıştırma hatası: %w (stderr: %s)", err, strings.TrimSpace(stderrBuf.String()))
	}

	_, _, _, nseFindings, parseErr := LoadNmapXMLFile(tempOut)
	if parseErr != nil {
		return nil, fmt.Errorf("nmap XML çıktısı okunamadı: %w", parseErr)
	}

	core.LogAudit("NMAP_NSE_COMPLETE", target, fmt.Sprintf("scripts=%d, findings=%d, duration=%.2fs", len(scripts), len(nseFindings), duration), "SUCCESS")
	core.LogSuccess("Nmap NSE denetimi tamamlandı: %d zafiyet/bilgi bulgusu kaydedildi (%.2f sn).", len(nseFindings), duration)

	return nseFindings, nil
}

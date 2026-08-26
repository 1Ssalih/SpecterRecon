package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// EnsureOutputDir ensures that the output directory exists.
func EnsureOutputDir(dir string) string {
	if dir == "" {
		dir = "output"
	}
	_ = os.MkdirAll(dir, 0755)
	return dir
}

// SaveJSON marshals and writes any data struct as indented JSON.
func SaveJSON(data interface{}, path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON marshal hatası: %w", err)
	}

	return os.WriteFile(path, bytes, 0644)
}

// LoadJSON reads and unmarshals JSON into the target struct.
func LoadJSON(path string, target interface{}) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("JSON okuma hatası (%s): %w", path, err)
	}

	if len(bytes) == 0 {
		return nil
	}

	return json.Unmarshal(bytes, target)
}

// SaveHosts writes hosts slice to JSON.
func SaveHosts(hosts []HostInfo, path string) error {
	if path == "" {
		path = "output/hosts.json"
	}
	return SaveJSON(hosts, path)
}

// LoadHosts reads hosts slice from JSON.
func LoadHosts(path string) ([]HostInfo, error) {
	if path == "" {
		path = "output/hosts.json"
	}
	var hosts []HostInfo
	err := LoadJSON(path, &hosts)
	return hosts, err
}

// SavePorts writes ports slice to JSON.
func SavePorts(ports []PortInfo, path string) error {
	if path == "" {
		path = "output/ports.json"
	}
	return SaveJSON(ports, path)
}

// LoadPorts reads ports slice from JSON.
func LoadPorts(path string) ([]PortInfo, error) {
	if path == "" {
		path = "output/ports.json"
	}
	var ports []PortInfo
	err := LoadJSON(path, &ports)
	return ports, err
}

// SaveServices writes services slice to JSON.
func SaveServices(services []ServiceDetail, path string) error {
	if path == "" {
		path = "output/services.json"
	}
	return SaveJSON(services, path)
}

// LoadServices reads services slice from JSON.
func LoadServices(path string) ([]ServiceDetail, error) {
	if path == "" {
		path = "output/services.json"
	}
	var services []ServiceDetail
	err := LoadJSON(path, &services)
	return services, err
}

// SaveVulns writes vulnerabilities slice to JSON.
func SaveVulns(vulns []VulnerabilityInfo, path string) error {
	if path == "" {
		path = "output/vulns.json"
	}
	return SaveJSON(vulns, path)
}

// LoadVulns reads vulnerabilities slice from JSON.
func LoadVulns(path string) ([]VulnerabilityInfo, error) {
	if path == "" {
		path = "output/vulns.json"
	}
	var vulns []VulnerabilityInfo
	err := LoadJSON(path, &vulns)
	return vulns, err
}

// SaveFindings writes findings to JSON and plain text.
func SaveFindings(findings []DirFuzzFinding, jsonPath, txtPath string) error {
	if jsonPath == "" {
		jsonPath = "output/dirs.json"
	}
	if err := SaveJSON(findings, jsonPath); err != nil {
		return err
	}

	if txtPath != "" {
		dir := filepath.Dir(txtPath)
		if dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0755)
		}
		file, err := os.Create(txtPath)
		if err != nil {
			return err
		}
		defer file.Close()

		for _, item := range findings {
			_, _ = fmt.Fprintf(file, "[%d] %s (size: %d bytes)\n", item.StatusCode, item.URL, item.ContentLength)
		}
	}
	return nil
}

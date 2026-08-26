package modules

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

// AuditContainerService tests Docker, Kubernetes, etcd, Consul, Prometheus endpoints for open access.
func AuditContainerService(ip string, port int, serviceName string, timeout time.Duration) core.ContainerFinding {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	finding := core.ContainerFinding{
		IP:       ip,
		Port:     port,
		Service:  serviceName,
		Severity: "INFO",
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	switch {
	case port == 2375 || port == 2376 || strings.Contains(serviceName, "docker"):
		finding.Service = "docker"
		testEndpoint(client, ip, port, "/version", "Docker API Açık! (Kimlik doğrulama yok)", &finding)
		testEndpoint(client, ip, port, "/containers/json", "Docker Konteyner Listesi Açık", &finding)

	case port == 6443 || port == 8080 || strings.Contains(serviceName, "k8s") || strings.Contains(serviceName, "kubernetes"):
		finding.Service = "kubernetes"
		testEndpoint(client, ip, port, "/api/v1", "Kubernetes Unauthenticated API Server", &finding)
		testEndpoint(client, ip, port, "/api/v1/namespaces", "Kubernetes Namespace Listesi Açık", &finding)

	case port == 2379 || port == 2380 || strings.Contains(serviceName, "etcd"):
		finding.Service = "etcd"
		testEndpoint(client, ip, port, "/version", "etcd Veritabanı API Açık (K8s Secret Riski)", &finding)
		testEndpoint(client, ip, port, "/v2/keys", "etcd Anahtar Listesi Açık", &finding)

	case port == 8500 || strings.Contains(serviceName, "consul"):
		finding.Service = "consul"
		testEndpoint(client, ip, port, "/v1/agent/self", "HashiCorp Consul API Açık", &finding)

	case port == 9090 || strings.Contains(serviceName, "prometheus"):
		finding.Service = "prometheus"
		testEndpoint(client, ip, port, "/metrics", "Prometheus Metrics Endpoint Açık", &finding)

	case port == 3000 || strings.Contains(serviceName, "grafana"):
		finding.Service = "grafana"
		testEndpoint(client, ip, port, "/api/health", "Grafana Web UI Açık", &finding)
	}

	return finding
}

func testEndpoint(client *http.Client, ip string, port int, path string, note string, f *core.ContainerFinding) {
	protos := []string{"http", "https"}
	for _, proto := range protos {
		targetURL := fmt.Sprintf("%s://%s:%d%s", proto, ip, port, path)
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "SpecterRecon/1.2")

		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()

			if resp.StatusCode == 200 && len(body) > 0 {
				f.Exposed = true
				f.Severity = "CRITICAL"
				f.Endpoints = append(f.Endpoints, targetURL)
				f.Notes = append(f.Notes, note)
				break
			}
		}
	}
}

// AuditContainerMultiple scans target services for DevOps/Container/Cloud exposures.
func AuditContainerMultiple(services []core.ServiceDetail, timeout time.Duration, outputFile string) ([]core.ContainerFinding, error) {
	containerPorts := map[int]string{
		2375: "docker",
		2376: "docker",
		6443: "kubernetes",
		8080: "k8s/http",
		2379: "etcd",
		2380: "etcd",
		8500: "consul",
		9090: "prometheus",
		3000: "grafana",
	}

	var targets []core.ServiceDetail
	for _, s := range services {
		if _, ok := containerPorts[s.Port]; ok || strings.Contains(s.ServiceName, "docker") || strings.Contains(s.ServiceName, "k8s") || strings.Contains(s.ServiceName, "etcd") {
			targets = append(targets, s)
		}
	}

	if len(targets) == 0 {
		return nil, nil
	}

	core.LogInfo("Container / Cloud DevOps Güvenlik Denetimi (Docker, K8s, etcd, Consul) başlatılıyor (%d servisi)...", len(targets))
	var findings []core.ContainerFinding

	for _, t := range targets {
		svc := t.ServiceName
		if mapped, ok := containerPorts[t.Port]; ok {
			svc = mapped
		}
		f := AuditContainerService(t.IP, t.Port, svc, timeout)
		if f.Exposed {
			findings = append(findings, f)
			core.LogWarning("🚨 CRITICAL CONTAINER/DEVOPS EXPOSURE (%s:%d - %s): %s", f.IP, f.Port, f.Service, strings.Join(f.Notes, " | "))
		}
	}

	if outputFile != "" {
		_ = core.SaveContainerFindings(findings, outputFile)
	}

	return findings, nil
}

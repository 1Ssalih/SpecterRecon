package modules

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/specter-recon/recon-tool/core"
)

// VerifyPortsWithHandshake verifies unverified ports (such as from stateless Masscan) using native TCP handshakes.
// Ports that fail to connect are flagged with Conflict=true (never deleted, for transparency).
func VerifyPortsWithHandshake(ports []core.PortInfo, concurrency int, timeout time.Duration) ([]core.PortInfo, []core.PortInfo) {
	if len(ports) == 0 {
		return nil, nil
	}

	if concurrency <= 0 {
		concurrency = 50
	}
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	core.LogInfo("Açık Port Doğrulama Katmanı: %d port için TCP handshake teyidi yapılıyor...", len(ports))

	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		resultPorts []core.PortInfo
		conflicts   []core.PortInfo
		sem         = make(chan struct{}, concurrency)
	)

	for _, p := range ports {
		// If port is already verified (e.g. from native scan or nmap), keep it verified
		if p.Verified {
			resultPorts = append(resultPorts, p)
			continue
		}

		wg.Add(1)
		go func(pi core.PortInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addr := net.JoinHostPort(pi.IP, strconv.Itoa(pi.Port))
			start := time.Now()
			conn, err := net.DialTimeout("tcp", addr, timeout)

			lat := float64(time.Since(start).Nanoseconds()) / 1e6

			mu.Lock()
			defer mu.Unlock()

			if err == nil {
				_ = conn.Close()
				pi.Verified = true
				pi.Conflict = false
				pi.ResponseTimeMs = &lat
				resultPorts = append(resultPorts, pi)
			} else {
				// Handshake failed or filtered - mark as Conflict
				pi.Verified = false
				pi.Conflict = true
				resultPorts = append(resultPorts, pi)
				conflicts = append(conflicts, pi)
				core.LogWarning("Port Teyit Çelişkisi (%s:%d [%s]): Masscan açık bildirdi ancak TCP bağlantısı kurulamadı (%v). Çelişki olarak kaydedildi.",
					pi.IP, pi.Port, pi.Source, err)
			}
		}(p)
	}

	wg.Wait()

	if len(conflicts) > 0 {
		core.LogWarning("Toplam %d portta kaynak çelişkisi tespit edildi (Masscan=Açık, Native=Kapalı/Filtreli).", len(conflicts))
	} else {
		core.LogSuccess("Tüm portlar native TCP handshake ile başarıyla teyit edildi (%d port).", len(resultPorts))
	}

	return resultPorts, conflicts
}

# Ağ Recon & Tarama Aracı — Proje Planı

> **Kapsam notu:** Bu araç yalnızca **yetkilendirilmiş** ortamlarda (kendi lab'ın, izinli pentest hedefleri, CTF, HackTheBox/TryHackMe gibi platformlar) kullanılmak üzere tasarlanmıştır. Uygulama açılışında hedefin izinli olduğunu onaylatan bir adım olacak.

---

## 1. Genel Mimari

Pipeline mantığı — her adım bir öncekinin çıktısını (JSON) girdi olarak alır, kendi verisini ekler ve zenginleştirilmiş JSON'u bir sonrakine devreder:

```
[DNS Enum (opsiyonel)] → [Host Discovery] → [Port/Service Scan] → [Banner Grab + Version Detect] → [CVE Match] → [Dir Bruteforce] → [Report]
         ↓                       ↓                    ↓                       ↓                         ↓                ↓              ↓
    ip_list.json           hosts.json          ports.json            services.json            vulns.json      dirs.json     report.html
```

**Target girdisi otomatik tespit edilir:**
- Girilen `--target` bir domain adıysa (örn. `example.com`) → önce DNS Enum adımı çalışır, A/AAAA kayıtları çözülür ve IP listesi çıkar, bu liste akışın geri kalanına girdi olur
- Girilen `--target` zaten bir IP veya CIDR (`192.168.1.0/24`) ise → DNS Enum tamamen atlanır, direkt Host Discovery'e geçilir
- Subdomain brute-force (SecList'teki subdomain wordlist'i ile daha kapsamlı DNS keşfi) default kapalı, `--subdomains` flag'i ile açılır — çünkü zaman alıcı ve her senaryoda gerekmez

Her modül bağımsız çalışabilmeli (örn. sadece port taraması istersen dosyayı elle de verebilmelisin) — bu hem test etmeyi hem de modülleri tek tek geliştirmeyi kolaylaştırır.

---

## 2. Teknoloji Kararı (güncellendi — Go)

Proje **Go** ile yazılıyor. Sebepleri:
- Concurrency native ve hafif (goroutine + channel) — port scan ve dir bruteforce gibi yüksek eşzamanlılık gerektiren modüllerde ciddi performans kazancı
- Tek binary çıktı — dağıtımı kolay, runtime bağımlılığı yok
- nmap/gobuster/ffuf gibi bu alandaki referans araçların çoğu da Go/C tabanlı

| Modül | Go Kütüphane/Paket |
|---|---|
| ARP/ICMP/SYN scan | `gopacket` + `gopacket/pcap` |
| TCP connect + banner grab | `net` (standart) + goroutine pool |
| HTTP istekleri (banner, dir fuzz) | `net/http` (standart) |
| CLI arayüz | `cobra` |
| Terminal görsel/progress | `pterm` |
| Config (YAML) | `gopkg.in/yaml.v3` |
| Veri saklama | JSON dosya (`encoding/json`, v1) → SQLite (v2) |
| CVE sorgulama | NVD REST API (`net/http`) |
| Rapor çıktısı | `html/template` → HTML |
| Wordlist | SecLists (git submodule) |

---

## 3. Modül Modül Plan

### Modül 0 — DNS Enumeration (`dns_enum.go`) — **[eklenen adım]**
- Sadece target bir domain adıysa çalışır (IP/CIDR verilirse otomatik atlanır)
- A/AAAA kayıt çözümü (varsayılan, hızlı)
- `--subdomains` flag'i açıksa: SecList'teki subdomain wordlist'i ile brute-force subdomain keşfi
- Çıktı: `ip_list.json` → `[{"hostname": "example.com", "ip": "93.184.216.34", "record_type": "A"}]`
- Bu liste Modül 1'e (Host Discovery) girdi olarak geçer

### Modül 1 — Host Discovery (`discovery.go`)
- Yerel ağdaysa: **ARP scan** (en güvenilir, scapy `ARP`/`Ether` ile)
- Farklı ağ/subnet ise: **ICMP ping sweep** + **TCP ping** (80, 443, 22 gibi yaygın portlara SYN) kombinasyonu
- Herhangi biri cevap verirse host "alive" sayılır
- Çıktı: `hosts.json` → `[{"ip": "192.168.1.10", "mac": "...", "discovery_method": "arp"}]`

### Modül 2 — Port & Servis Tespiti (`portscan.go`)
- Async TCP connect scan (root gerektirmeyen versiyon önce, SYN scan opsiyonel/gelişmiş mod)
- Port aralığı config'den ayarlanabilir (top-1000, full 65535, custom liste)
- Concurrency limit (semaphore) — ağı/hedefi boğmamak için
- Çıktı: `ports.json` → `[{"ip": "...", "port": 80, "state": "open"}]`

### Modül 3 — Banner Grabbing & Versiyon Tespiti (`banner.go`)
- Her açık port için:
  - Ham banner okuma (socket connect + ilk N byte oku, timeout'lu)
  - HTTP portlarında `HEAD /` isteği → `Server`, `X-Powered-By` header'ları
  - Bilinen servis imzalarını regex ile eşleştirip versiyon çıkarma (örn. `Apache/2.4.54`)
- **Veri formatı: JSON** (senin sorduğun XML/JSON kararı — JSON kazandı, sebebi: Python'da native, insan-okunur, ileride SQLite'a taşımak kolay)

Alan isimleri kağıt plandaki şemaya göre netleştirildi:

```json
{
  "source_ip": "192.168.1.10",
  "scan_date": "2026-08-26T10:00:00Z",
  "open_ports": [
    {
      "port_name": 80,
      "port_description": "http",
      "service_version": "2.4.54",
      "service_detay": "Apache httpd (Ubuntu build)",
      "banner_raw": "Apache/2.4.54 (Ubuntu)",
      "source_ip": "192.168.1.10",
      "state": "open"
    }
  ]
}
```

### Modül 4 — CVE Eşleştirme (`vuln_match.go`) — **[eklenen adım]**
- Modül 3'ten çıkan `service_name` + `service_version` ile NVD API'ye sorgu
- Bulunan CVE'leri şiddet (CVSS score) sırasına göre listele
- Çıktı: `vulns.json`
- Bu adım projeyi "recon" seviyesinden "vulnerability assessment" seviyesine çıkarıyor — CV/portfolyo değeri yüksek

### Modül 5 — Dizin/Dosya Bruteforce (`dirfuzz.go`)
- Sadece HTTP/HTTPS servisi tespit edilen portlarda çalışır (gereksiz tarama yapmamak için)
- **Akıllı wordlist seçimi**: Modül 3'ten gelen `service_description`/`service_detay` bilgisine bakılarak, genel bir wordlist yerine SecList içindeki **servise özel** wordlist seçilir
  - Örn. tespit edilen servis "Jenkins" ise → SecList'in Jenkins'e özel path listesi kullanılır
  - Tespit edilen servis "Apache"/"nginx" gibi genel bir web sunucusuysa → o teknolojiye özel liste (varsa) veya genel `raft-medium-directories.txt` kullanılır
  - Servis tanınamazsa (eşleşme bulunamazsa) → fallback olarak genel wordlist kullanılır
  - Bu eşleştirme mantığı ayrı bir config dosyasında (`service_wordlist_map.yaml`) tutulur, böylece yeni servis-wordlist eşleşmeleri kod değiştirmeden eklenebilir:
    ```yaml
    jenkins: "wordlists/SecLists/Discovery/Web-Content/Jenkins.txt"
    apache: "wordlists/SecLists/Discovery/Web-Content/Apache.txt"
    wordpress: "wordlists/SecLists/Discovery/Web-Content/CMS/wordpress.txt"
    default: "wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
    ```
- Async fuzzer: seçilen wordlist'i satır satır oku, her path'e istek at, status code'a göre logla (200/301/302/403 = ilgi çekici)
- Rate limiting (istekler arası ms gecikme, config'den ayarlanabilir) — stealth/agresif mod seçimi
- Bulunan gerçek path'ler ayrı çıktıya yazılır: `findings.txt` (hangi wordlist/servis eşleşmesiyle bulunduğu bilgisiyle birlikte)
- SecLists git submodule olarak projeye eklenecek

### Modül 6 — Raporlama (`report.go`) — **[eklenen adım]**
- Tüm JSON çıktılarını birleştirip Jinja2 template ile HTML rapor üret
- Özet tablo: host → açık portlar → servisler → bulunan CVE'ler → bulunan dizinler
- Bonus: PDF export (weasyprint veya benzeri)

---

## 4. Proje Klasör Yapısı

```
recon-tool-go/
├── main.go                   # cobra CLI giriş noktası
├── cmd/
│   └── root.go                # cobra kök komut
├── config.yaml                # hedef, port range, thread sayısı, wordlist yolu
├── modules/
│   ├── dns_enum.go
│   ├── discovery.go
│   ├── portscan.go
│   ├── banner.go
│   ├── vuln_match.go
│   ├── dirfuzz.go
│   └── report.go
├── core/
│   ├── models.go              # struct tanımları (Host, Port, Service, Finding)
│   ├── storage.go             # JSON okuma/yazma helper'ları
│   └── logger.go              # loglama (log/slog)
├── wordlists/
│   ├── SecLists/               # git submodule
│   └── service_wordlist_map.yaml  # servis → wordlist eşleştirme config'i
├── output/
│   ├── ip_list.json
│   ├── hosts.json
│   ├── ports.json
│   ├── vulns.json
│   ├── findings.txt
│   └── report.html
├── templates/
│   └── report.html.tmpl
├── go.mod
├── go.sum
└── README.md
```

---

## 5. Güvenlik & Etik Guardrail'ler (kritik)

1. **Scope onayı**: Uygulama başlarken kullanıcıdan "bu hedefi taramaya yetkim var" onayı isteyen bir adım (basit bir `--i-have-permission` flag'i veya interaktif onay)
2. **Rate limiting default açık**: Agresif tarama default olmamalı, kullanıcı bilerek `--aggressive` gibi bir flag ile açmalı
3. **Loglama**: Her çalıştırmada ne zaman/hangi hedefe/hangi modüllerin çalıştığı ayrı log dosyasına yazılmalı — hesap verebilirlik için
4. **Yerel ağ dışı taramalarda uyarı**: Aracın public IP'lere karşı kullanımı hukuki risk taşır, bu konuda README'de net uyarı olmalı

---

## 6. Geliştirme Sırası (Roadmap)

| Faz | İçerik | Hedef |
|---|---|---|
| **Faz 0** | Proje iskeleti, config sistemi, JSON model tanımları | Temel altyapı |
| **Faz 0.5** | DNS Enum modülü (domain → IP listesi, opsiyonel subdomain brute-force) | ip_list.json |
| **Faz 1** | Host Discovery modülü (ARP + ICMP + TCP ping) | Çalışan host listesi |
| **Faz 2** | Port scan + banner grab (Modül 2+3 birleşik) | services.json |
| **Faz 3** | CLI + rich progress bar entegrasyonu | Kullanılabilir terminal deneyimi |
| **Faz 4** | Dir bruteforce + SecLists entegrasyonu | findings.txt |
| **Faz 5** | CVE eşleştirme (NVD API) | vulns.json |
| **Faz 6** | HTML rapor üretimi | report.html |
| **Faz 7 (opsiyonel)** | SSL/TLS analiz, screenshot alma (Playwright), SQLite'a geçiş | Gelişmiş özellikler |

---

## 7. İlk Adım Önerisi

Faz 0 + Faz 1 ile başlamanı öneririm: proje iskeletini kurup Host Discovery modülünü çalışır hale getirmek. Bu sana hem mimarinin oturup oturmadığını erken görme fırsatı verir hem de scapy ile çalışmaya ısınmanı sağlar.

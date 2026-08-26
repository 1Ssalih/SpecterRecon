# Ağ Recon & Tarama Aracı — Proje Planı

> **Kapsam notu:** Bu araç yalnızca **yetkilendirilmiş** ortamlarda (kendi lab'ın, izinli pentest hedefleri, CTF, HackTheBox/TryHackMe gibi platformlar) kullanılmak üzere tasarlanmıştır. Uygulama açılışında hedefin izinli olduğunu onaylatan bir adım olacak.

---

## 1. Genel Mimari

Pipeline mantığı — her adım bir öncekinin çıktısını (JSON) girdi olarak alır, kendi verisini ekler ve zenginleştirilmiş JSON'u bir sonrakine devreder:

```
[Host Discovery] → [Port/Service Scan] → [Banner Grab + Version Detect] → [CVE Match] → [Dir Bruteforce] → [Report]
       ↓                    ↓                       ↓                         ↓                ↓              ↓
   hosts.json         ports.json            services.json            vulns.json      dirs.json     report.html
```

Her modül bağımsız çalışabilmeli (örn. sadece port taraması istersen dosyayı elle de verebilmelisin) — bu hem test etmeyi hem de modülleri tek tek geliştirmeyi kolaylaştırır.

---

## 2. Teknoloji Kararı (netleştirildi)

**Python 3.11+ / asyncio** ile başlıyoruz. Sebepleri:
- Hızlı prototipleme, senin öğrenme sürecine daha uygun
- `scapy`, `aiohttp`, `rich` gibi kütüphanelerle her adımı hızlı kurabiliyoruz
- İleride darboğaz olan modülü (muhtemelen dir bruteforce veya port scan) Go'ya taşıma opsiyonu açık kalıyor

| Modül | Kütüphane |
|---|---|
| ARP/ICMP/SYN scan | `scapy` |
| Async TCP connect + banner grab | `asyncio` + `socket` |
| HTTP istekleri (banner, dir fuzz) | `httpx` (async) |
| CLI arayüz | `typer` |
| Terminal görsel/progress | `rich` |
| Veri saklama | JSON dosya (v1) → SQLite (v2) |
| CVE sorgulama | NVD REST API (`requests`/`httpx`) |
| Rapor çıktısı | Jinja2 → HTML |
| Wordlist | SecLists (git submodule) |

---

## 3. Modül Modül Plan

### Modül 1 — Host Discovery (`discovery.py`)
- Yerel ağdaysa: **ARP scan** (en güvenilir, scapy `ARP`/`Ether` ile)
- Farklı ağ/subnet ise: **ICMP ping sweep** + **TCP ping** (80, 443, 22 gibi yaygın portlara SYN) kombinasyonu
- Herhangi biri cevap verirse host "alive" sayılır
- Çıktı: `hosts.json` → `[{"ip": "192.168.1.10", "mac": "...", "discovery_method": "arp"}]`

### Modül 2 — Port & Servis Tespiti (`portscan.py`)
- Async TCP connect scan (root gerektirmeyen versiyon önce, SYN scan opsiyonel/gelişmiş mod)
- Port aralığı config'den ayarlanabilir (top-1000, full 65535, custom liste)
- Concurrency limit (semaphore) — ağı/hedefi boğmamak için
- Çıktı: `ports.json` → `[{"ip": "...", "port": 80, "state": "open"}]`

### Modül 3 — Banner Grabbing & Versiyon Tespiti (`banner.py`)
- Her açık port için:
  - Ham banner okuma (socket connect + ilk N byte oku, timeout'lu)
  - HTTP portlarında `HEAD /` isteği → `Server`, `X-Powered-By` header'ları
  - Bilinen servis imzalarını regex ile eşleştirip versiyon çıkarma (örn. `Apache/2.4.54`)
- **Veri formatı: JSON** (senin sorduğun XML/JSON kararı — JSON kazandı, sebebi: Python'da native, insan-okunur, ileride SQLite'a taşımak kolay)

```json
{
  "source_ip": "192.168.1.10",
  "scan_date": "2026-08-26T10:00:00Z",
  "open_ports": [
    {
      "port": 80,
      "service_name": "http",
      "service_description": "Apache httpd",
      "service_version": "2.4.54",
      "banner_raw": "Apache/2.4.54 (Ubuntu)",
      "state": "open"
    }
  ]
}
```

### Modül 4 — CVE Eşleştirme (`vuln_match.py`) — **[eklenen adım]**
- Modül 3'ten çıkan `service_name` + `service_version` ile NVD API'ye sorgu
- Bulunan CVE'leri şiddet (CVSS score) sırasına göre listele
- Çıktı: `vulns.json`
- Bu adım projeyi "recon" seviyesinden "vulnerability assessment" seviyesine çıkarıyor — CV/portfolyo değeri yüksek

### Modül 5 — Dizin/Dosya Bruteforce (`dirfuzz.py`)
- Sadece HTTP/HTTPS servisi tespit edilen portlarda çalışır (gereksiz tarama yapmamak için)
- Async fuzzer: SecLists wordlist'i satır satır oku, her path'e istek at, status code'a göre logla (200/301/302/403 = ilgi çekici)
- Rate limiting (istekler arası ms gecikme, config'den ayarlanabilir) — stealth/agresif mod seçimi
- Eşleşen (yani cevap dönen) path'ler ayrı çıktıya yazılır: `findings.txt`
- SecLists git submodule olarak projeye eklenecek (`raft-medium-directories.txt` ile başla, sonra genişlet)

### Modül 6 — Raporlama (`report.py`) — **[eklenen adım]**
- Tüm JSON çıktılarını birleştirip Jinja2 template ile HTML rapor üret
- Özet tablo: host → açık portlar → servisler → bulunan CVE'ler → bulunan dizinler
- Bonus: PDF export (weasyprint veya benzeri)

---

## 4. Proje Klasör Yapısı

```
recon-tool/
├── main.py                  # typer CLI giriş noktası
├── config.yaml               # hedef, port range, thread sayısı, wordlist yolu
├── modules/
│   ├── discovery.py
│   ├── portscan.py
│   ├── banner.py
│   ├── vuln_match.py
│   ├── dirfuzz.py
│   └── report.py
├── core/
│   ├── models.py             # dataclass/pydantic modelleri (Host, Port, Service, Finding)
│   ├── storage.py            # JSON okuma/yazma helper'ları
│   └── logger.py             # loglama
├── wordlists/
│   └── SecLists/             # git submodule
├── output/
│   ├── hosts.json
│   ├── ports.json
│   ├── vulns.json
│   ├── findings.txt
│   └── report.html
├── templates/
│   └── report.html.j2
├── requirements.txt
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

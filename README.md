<div align="center">

# ⚡ SpecterRecon (v2.0.0 — Universal Pentest Edition)
### *Universal High-Performance Infrastructure & Application Security Assessment Engine in Go*

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![Concurrency](https://img.shields.io/badge/Concurrency-Goroutines%20%2B%20Worker%20Pools-00f2fe?style=for-the-badge&logo=fastapi&logoColor=black)](#)
[![CLI Engine](https://img.shields.io/badge/CLI-Cobra%20%2B%20PTerm-9333EA?style=for-the-badge&logo=gnometerminal&logoColor=white)](#)
[![NVD API & CVE Matcher](https://img.shields.io/badge/Vulnerabilities-NVD%20API%20%2B%20CVSS%20v3.1-ff3366?style=for-the-badge&logo=security&logoColor=white)](#)
[![Cross-Platform](https://img.shields.io/badge/OS-Windows%20%7C%20Linux%20%7C%20macOS-success?style=for-the-badge&logo=linux&logoColor=white)](#)

<br>

```ascii
  ____                  _             ____                     
 / ___| _ __   ___  ___| |_ ___ _ __ |  _ \ ___  ___ ___  _ __ 
 \___ \| '_ \ / _ \/ __| __/ _ \ '__|| |_) / _ \/ __/ _ \| '_ \ 
  ___) | |_) |  __/ (__| ||  __/ |   |  _ <  __/ (_| (_) | | | |
 |____/| .__/ \___|\___|\__\___|_|   |_| \_\___|\___\___/|_| |_|
       |_|                                                     
    -- Universal Recon & Vulnerability Scanner for All Pentests --   
```

<p align="center">
  <b>SpecterRecon v2.0.0</b>, siber güvenlik uzmanları, sızma testi (pentest) ekipleri ve CTF/lab araştırmacıları için geliştirilmiş; <b>Web Uygulamaları, Ağ Altyapısı, Active Directory, Veritabanları, Cloud/DevOps, IoT/OT ve SSL/TLS denetimlerini</b> tek bir bağımsız binary dosyasında toplayan <b>130+ kontrollük evrensel güvenlik tarama motorudur</b>.
</p>

---

</div>

## 📌 Neden SpecterRecon v2.0.0?

Geleneksel tarayıcılar genellikle tek bir alana odaklanır (sadece web, sadece port veya sadece network). **SpecterRecon v2.0.0**, her türlü sızma testinde (Web, Ağ, AD, DB, Cloud, IoT) kullanılabilecek **profil tabanlı modüler boru hattı (pipeline) mimarisine** sahiptir:

1. **🌐 Web Uygulama Pentest:** Security Headers (HSTS, CSP, X-Frame-Options), CORS Misconfiguration, Tehlikeli HTTP Metodları (TRACE/PUT/DELETE), GraphQL Introspection, Cookie Security, Reflected XSS, Error-Based SQLi, Open Redirect ve Deterministik Dizin Fuzzing.
2. **🏢 Ağ & Altyapı Pentest:** ICMP/TCP Host Keşfi, Goroutine Port Taraması, Banner Grabbing, FTP Anonymous Login & Write Access, SMTP Open Relay & VRFY User Enum, UDP 161 SNMP Community String Brute-Force, SSH Zayıf Algoritma Analizi, NFS Export Denetimi.
3. **🖥️ Active Directory / Windows Pentest:** SMB Null Session (anonim erişim), SMBv1 (EternalBlue/MS17-010 riski), SMB Signing (NTLM Relay riski), NetBIOS Query, Anonymous LDAP Bind, Active Directory Domain & Root DSE Naming Context Sorgusu.
4. **🗄️ Veritabanı Pentest:** Redis NO AUTH Unprotected Access, MongoDB Unprotected Access, Memcached Anonymous Access, PostgreSQL Trust Authentication, MySQL Handshake, MSSQL & Elasticsearch denetimi.
5. **🐳 Cloud & DevOps Pentest:** Docker Engine API (2375/2376) Unauthenticated Access, Kubernetes API Server (6443/8080) Anonymous Access, etcd (2379/2380) Key Exposure, Consul (8500), Prometheus Metrics (9090), Grafana (3000).
6. **🔑 Default Credential Pentest:** FTP, SSH, HTTP Basic Auth, MySQL ve Redis için güvenli varsayılan kimlik bilgisi (default creds) tespiti.
7. **🏭 IoT / OT Pentest:** Modbus TCP (502 PLC), RTSP Kamera (554 Video Stream), VNC Uzaktan Masaüstü (5900 RFB Şifresiz Erişim).
8. **🔒 SSL/TLS Audit:** Sertifika son kullanma tarihi, self-signed sertifika, zayıf protokol (SSLv3, TLS 1.0, TLS 1.1) ve zayıf cipher tespiti.

---

## 🎯 Tarama Profilleri (`--profile`)

SpecterRecon, hedefe ve test türüne uygun profil ile çalıştırılabilir:

```bash
# 🌐 Sadece Web Pentest
.\specter-recon.exe scan target.com --profile web --authorized

# 🏢 Sadece Ağ Altyapı Pentest (FTP, SMB, SMTP, SNMP, SSH)
.\specter-recon.exe scan 192.168.1.0/24 --profile network --authorized

# 🖥️ Active Directory / Windows Ortamı Pentest (SMB + LDAP)
.\specter-recon.exe scan 192.168.1.10 --profile ad --authorized

# 🗄️ Veritabanı Güvenlik Denetimi (Redis, Mongo, Postgres, MySQL)
.\specter-recon.exe scan 192.168.1.10 --profile database --authorized

# 🔒 SSL/TLS Sertifika & Protokol Audit
.\specter-recon.exe scan example.com --profile ssl --authorized

# 🐳 Cloud & DevOps Container Denetimi (Docker, K8s, etcd)
.\specter-recon.exe scan 192.168.1.10 --profile cloud --authorized

# 🚀 HEPSİ (Eksiksiz Tam Pentest Taraması)
.\specter-recon.exe fullscan 192.168.1.10 --authorized
```

---

## 📦 Proje Dizin Ağacı

```
Cyber-Security/
├── main.go                  # Uygulama ana giriş noktası
├── go.mod                   # Go modül tanımı (Go 1.21+)
├── config.yaml              # Merkezi tarama ve port yapılandırması
├── README.md                # Kapsamlı v2.0.0 dokümantasyonu
│
├── cmd/                     # Cobra CLI komutları
│   ├── root.go              # Yasal izin (--authorized) kontrolü
│   ├── scan.go              # Profil tabanlı boru hattı komutu (--profile)
│   ├── fullscan.go          # 🆕 Tüm adımları tek komutla çalıştıran kısayol
│   ├── ssl.go               # 🆕 SSL/TLS audit komutu
│   ├── smb.go               # 🆕 SMB null session & signing audit komutu
│   ├── creds.go             # 🆕 Default credential testing komutu
│   ├── dns.go               # DNS Enumeration komutu
│   ├── discover.go          # Host keşif komutu
│   ├── portscan.go          # Port tarama komutu
│   ├── banner.go            # Banner grabbing komutu
│   ├── vuln.go              # CVE zafiyet analiz komutu
│   ├── dirfuzz.go           # Web fuzzer komutu
│   └── report.go            # Rapor üretim komutu
│
├── core/                    # Çekirdek yardımcılar & Veri Modelleri
│   ├── models.go            # 🆕 Tüm pentest modülleri için Go struct şemaları
│   ├── storage.go           # 🆕 JSON saklama + Genişletilmiş SaveSummaryTxt
│   └── logger.go            # 🆕 PTerm konsol tabloları (PrintSslTable, PrintSmbTable...)
│
└── modules/                 # Güvenlik Modülleri
    ├── ssl_tls.go           # 🆕 SSL/TLS Sertifika & Zayıf Protokol Audit
    ├── http_audit.go        # 🆕 HTTP Security Headers, CORS, GraphQL, Methods
    ├── ftp_enum.go          # 🆕 FTP Anonymous Login, Write Check (MKD), FTPS
    ├── smb.go               # 🆕 SMB Null Session, SMBv1, SMB Signing, NetBIOS Query
    ├── ssh_audit.go         # 🆕 SSH KEXINIT Zayıf Algoritma & Banner Analizi
    ├── db_enum.go           # 🆕 Redis NOAUTH, Mongo Unprotected, Postgres Trust Auth...
    ├── smtp.go              # 🆕 SMTP Open Relay, VRFY User Enum, STARTTLS
    ├── snmp.go              # 🆕 UDP 161 SNMP Community Brute & sysDescr Query
    ├── creds.go             # 🆕 Default Credential Testing Engine
    ├── container.go         # 🆕 Docker API, Kubernetes API, etcd, Consul, Prometheus
    ├── ldap.go              # 🆕 Anonymous LDAP Bind & Active Directory Domain Query
    ├── webvuln.go           # 🆕 Reflected XSS, Error-Based SQLi, Open Redirect
    ├── nfs.go               # 🆕 NFS 2049 RPC Export & Mount Check
    ├── iot.go               # 🆕 Modbus TCP (PLC), RTSP Camera, VNC RFB Check
    ├── portscan.go          # Goroutine Worker Pool Port Tarayıcısı
    ├── discovery.go         # Host Keşfi (ARP / ICMP / TCP ping)
    ├── banner.go            # Banner Grabbing & Versiyon Çıkarımı
    ├── vulnmatch.go         # NVD API & Offline CVE Eşleştirici
    ├── dirfuzz.go           # Deterministik Akıllı Web Fuzzer
    ├── report.go            # HTML Rapor Üreticisi
    └── modules_test.go      # Go birim testleri (8 test)
```

---

## 💻 Kullanım Örnekleri

### 1. Tam Otomatik Pentest (`fullscan` veya `scan --profile full`)

```bash
# Hedef IP üzerinde tüm 130+ kontrolü çalıştır
.\specter-recon.exe fullscan 192.168.1.10 --authorized

# Domain üzerinde subdomain discovery dahil tam pentest
.\specter-recon.exe scan example.com --profile full --subdomains --authorized
```

### 2. Modülleri Tek Başına Çalıştırma

```bash
# 🔒 SSL/TLS Sertifika ve Protokol Audit
.\specter-recon.exe ssl 192.168.1.10:443

# 🖥️ SMB Null Session & Signing Denetimi
.\specter-recon.exe smb 192.168.1.10 --authorized

# 🔑 Varsayılan Credential Tespiti
.\specter-recon.exe creds 192.168.1.10 --authorized

# 📂 Web Dizin Fuzzing
.\specter-recon.exe dirfuzz http://192.168.1.10:8080 --authorized
```

---

## 📄 `output/summary.txt` Örnek Çıktısı

Her taramadan sonra otomatik oluşturulan konsolide insan-okunabilir özet:

```
=== SpecterRecon Tarama Özeti ===
Hedef : 192.168.1.10
Tarih : 2026-08-26 16:30:00
Süre  : 18.45 saniye

[HOSTLAR] (1)
  + 192.168.1.10 [tcp_ping, alive]

[AÇIK PORTLAR] (6)
  + 192.168.1.10:21     ftp             [open]
  + 192.168.1.10:22     ssh             [open]
  + 192.168.1.10:443    https           [open]
  + 192.168.1.10:445    microsoft-ds    [open]
  + 192.168.1.10:2375   docker          [open]
  + 192.168.1.10:6379   redis           [open]

[SSL/TLS BULGULARI] (2)
  !! 192.168.1.10:443 — Zayıf protokol destekleniyor: TLSv1.0
  !! 192.168.1.10:443 — Self-Signed (Öz İmzalı) Sertifika

[SMB BULGULARI] (2)
  !! 192.168.1.10:445 — NULL SESSION AKTİF
  !! 192.168.1.10:445 — SMB SIGNING DEVRE DIŞI (relay riski)

[FTP BULGULARI] (1)
  !! 192.168.1.10:21 — ANONYMOUS FTP GİRİŞİ MÜMKÜN

[VERİTABANI BULGULARI] (1)
  !! 192.168.1.10:6379 [redis] — REDIS AUTH OLMADAN ERİŞİLEBİLİR!

[CONTAINER/CLOUD BULGULARI] (1)
  !! 192.168.1.10:2375 [docker] — KİMLİK DOĞRULAMASIZ ERİŞİM AÇIK

=== ÖZET ===
  Hostlar        : 1
  Açık Portlar   : 6
  Zafiyetler     : 2 toplam (1 kritik/yüksek)
  Web Bulguları  : 4 toplam
  Rapor          : output/report.html
  Süre           : 18.45 saniye
```

---

## 🧪 Testleri Çalıştırma

```bash
# Tüm Go birim testlerini yürüt (8 test)
go test -v ./modules/...
```

---

## ⚖️ Yasal Uyarı ve Etik Bildirimi

> **ÖNEMLİ:** Bu araç yalnızca **yasal izin alınmış sistemler**, yetkili sızma testi sözleşmeleri, laboratuvar ortamları ve CTF yarışmaları için tasarlanmıştır. İzin alınmamış üçüncü taraf sistemlere karşı tarama yapmak yasalara aykırıdır. Geliştiriciler, aracın kötüye kullanımından sorumlu tutulamaz.

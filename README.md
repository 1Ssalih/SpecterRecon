<div align="center">

# ⚡ SpecterRecon (v0.8.0)
### *Yüksek Performanslı, Bağlam Duyarlı ve Hibrit Ağ Keşif & Zafiyet Görünürlük Motoru*

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![CI Status](https://img.shields.io/badge/CI-GitHub_Actions-blue?style=for-the-badge&logo=githubactions&logoColor=white)](.github/workflows/ci.yml)
[![Version](https://img.shields.io/badge/Release-v0.8.0_Enterprise-00f2fe?style=for-the-badge&logo=semver&logoColor=black)](#)
[![Fuzzing](https://img.shields.io/badge/Fuzzing-Catch--All_Baseline_%2B_Secret_Scanner-brightgreen?style=for-the-badge&logo=shield&logoColor=white)](#)
[![Hybrid Recon](https://img.shields.io/badge/Engine-Go_Native_%7C_Masscan_%7C_Nmap_NSE-red?style=for-the-badge&logo=target&logoColor=white)](#)

<br>

```ascii
  ____                  _             ____                     
 / ___| _ __   ___  ___| |_ ___ _ __ |  _ \ ___  ___ ___  _ __ 
 \___ \| '_ \ / _ \/ __| __/ _ \ '__|| |_) / _ \/ __/ _ \| '_ \ 
  ___) | |_) |  __/ (__| ||  __/ |   |  _ <  __/ (_| (_) | | | |
 |____/| .__/ \___|\___|\__\___|_|   |_| \_\___|\___\___/|_| |_|
       |_|                                                     
    -- Context-Aware High Performance Reconnaissance Engine --   
```

<p align="center">
  <b>SpecterRecon</b>, sızma testi uzmanları, siber güvenlik araştırmacıları, kırmızı takım (Red Team) ve SOC analistleri için <b>Go (Golang)</b> ile sıfırdan geliştirilmiş; <b>DNS Altyapı Güvenliği (AXFR Zone Transfer, Wildcard Tespiti, Subdomain Takeover), Canlı Host Keşfi, Yüksek Hızlı Port Tarama (Native Goroutine / Masscan Hibrit), Derin Servis & İşletim Sistemi Parmak İzi (SMB2 NTLMSSP Build, LDAP RootDSE FuncLevel, MSSQL TDS, WinRM SOAP, RDP TLS, VNC RFB, Fortinet FSSO), WAF/CDN Tespiti (Akamai, Cloudflare, AWS), Catch-All Korumalı ve Pasif Kredansiyel/Secret Sızıntı Taramalı Akıllı Web Fuzzing (SecLists & Dirb Hibrit), Nmap NSE Zafiyet Eşleme ve SOC Dashboard Raporlama</b> süreçlerini tek bir bağımsız ikili dosyada (zero-dependency binary) birleştiren kurumsal düzeyde keşif motorudur.
</p>

---

</div>

## 📌 İçindekiler

- [🎯 1. Temel Felsefe ve Mimari İlkeler](#-1-temel-felsefe-ve-mimari-i̇lkeler)
- [⚡ 2. Modüler Mimari ve Yetenek Matrisi](#--2-modüler-mimari-ve-yetenek-matrisi)
- [🔄 3. Tam Otomatik Keşif Boru Hattı (Recon Pipeline)](#-3-tam-otomatik-keşif-boru-hattı-recon-pipeline)
- [🎯 4. Tarama Profilleri (`--profile`)](#-4-tarama-profilleri---profile)
- [🌐 5. DNS & Altyapı Güvenlik Analizi Motoru](#-5-dns--altyapı-güvenlik-analizi-motoru)
- [🔬 6. Derin Servis & İşletim Sistemi (OS) Tespit Motoru](#-6-derin-servis--i̇şletim-sistemi-os-tespit-motoru)
- [📂 7. Akıllı Web Fuzzing, Sızıntı Taraması & Özyinelemeli Keşif](#-7-akıllı-web-fuzzing-sızıntı-taraması--özyinelemeli-keşif)
- [🛡️ 8. Port Doğrulama ve Çelişki Çözümleme Katmanı (Conflict Resolution)](#-8-port-doğrulama-ve-çelişki-çözümleme-katmanı-conflict-resolution)
- [💻 9. İnteraktif Konsol Modu (Readline / Metasploit Style)](#-9-i̇nteraktif-konsol-modu-readline--metasploit-style)
- [📁 10. Proje Dizin Yapısı](#-10-proje-dizin-yapısı)
- [📥 11. Kurulum ve Derleme](#-11-kurulum-ve-derleme)
- [🚀 12. Kapsamlı Komut Satırı Kullanım Kılavuzu (CLI Examples)](#-12-kapsamlı-komut-satırı-kullanım-kılavuzu-cli-examples)
- [⚙️ 13. Yapılandırma (`config.yaml`)](#️-13-yapılandırma-configyaml)
- [📊 14. SOC Raporlama ve Çıktı Formatları](#-14-soc-raporlama-ve-çıktı-formatları)
- [⚖️ 15. Yasal Uyarı ve Lisans](#️-15-yasal-uyarı-ve-lisans)

---

## 🎯 1. Temel Felsefe ve Mimari İlkeler

Modern kurumsal ağlarda Active Directory ormanları, mikroservis mimarileri, ters vekil (reverse proxy) katmanları ve WAF/CDN altyapıları yer alır. Geleneksel araçların parça parça çalıştırılması hem bağlantı darboğazlarına hem de binlerce sahte pozitif (false-positive) sonuca yol açar.

**SpecterRecon'un Tasarım Prensipleri:**
1. **Sıfır Dış Bağımlılık (Zero-Dependency & Portability):** Harici araçlar (Nmap/Masscan) sistemde yüklü olmasa bile, Go'nun yerel eşzamanlı worker pool motoru ve gömülü wordlist sistemi (`//go:embed`) sayesinde hem Linux hem de Windows üzerinde tek başına eksiksiz çalışır.
2. **Hibrit Güç:** Sistemde Masscan veya Nmap mevcutsa, Masscan'in saniyede yüzbinlerce paketlik hızından ve Nmap'in zengin NSE zafiyet script kütüphanesinden otomatik faydalanır.
3. **Akıllı Çoklu Host Pacing & Soket Yönetimi:** Çoklu IP ve Domain Controller taramalarında hedefi kilitlememek veya TCP Reset yememek için per-host mutex kilidi ve kademeli gecikme (pacing) uygular.
4. **Sıfır Sahte Bulgu (Zero False-Positive):** Fuzzing öncesi 3 aşamalı Catch-All ve Soft-404 baseline analizi yaparak sahte 301/302 yönlendirmelerini ayıklar.
5. **Kimlik Doğrulamasız Derin Bilgi Toplama:** SMB2 NTLMSSP Challenge paketleri, LDAP RootDSE ASN.1 sorguları, MSSQL TDS 7.x handshake'leri ve RDP TLS müzakereleriyle hedefe oturum açmadan tam işletim sistemi build'i, Active Directory domain adı ve sunucu sertifika bilgilerini elde eder.
6. **Pasif Sızıntı Denetimi:** Keşif sırasında sunucu yanıtlarını pasif olarak tarayarak sızan API anahtarlarını, özel anahtarları (RSA/SSH), JWT token'ları, DB bağlantı adreslerini ve framework hata/debug sayfalarını yakalar.

---

## ⚡ 2. Modüler Mimari ve Yetenek Matrisi

| Modül | Yetenek Kapsamı | Tespit Edilen Zafiyet / Çıktı |
| :--- | :--- | :--- |
| **DNS Altyapı Güvenliği** | A, AAAA, CNAME, MX, TXT, NS, SOA, Active Directory SRV, PTR | **DNS Zone Transfer (AXFR) Açığı**, **Wildcard DNS**, **Subdomain Takeover** (25+ Bulut Sağlayıcı) |
| **Canlı Host Keşfi** | ARP, ICMP Echo, TCP SYN Ping (Milisaniye hassasiyetli gecikme ölçümü) | Ağ topolojisi, erişilebilir canlı IP listesi |
| **Port Tarama & Doğrulama** | Native Go TCP Connect Worker Pool veya Masscan Subprocess entegrasyonu | Açık portlar, port yanıt süreleri, **Conflicting Ports (Çelişki Tespiti)** |
| **Derin Servis Parmak İzi** | SMB2, LDAP, MSSQL, WinRM, RDP, VNC, FSSO, Redis, Postgres, MySQL, Oracle TNS, SSH, FTP, SMTP | Windows Server Build (2012R2/2016/2019/2022/2025), AD Domain/Forest, SQL Server Build, FQDN |
| **WAF & CDN Tespiti** | Akamai (`AkamaiGHost`), Cloudflare, AWS CloudFront, Imperva, F5 BIG-IP, Sucuri | WAF arkasındaki gerçek servisler, dinamik `Host` header eşleştirmesi |
| **Favicon MMH3 Motoru** | Shodan %100 uyumlu 32-bit MurmurHash3 hesaplaması | Spring Boot, Jenkins, Grafana, phpMyAdmin, WordPress, VMware vCenter vb. |
| **Akıllı Web Fuzzing** | Catch-All Baseline Filtresi, SecLists Entegrasyonu, Dinamik Teknoloji Uzantı Genişletmesi | Gizli dizinler, `.env`, `.git`, `.bak`, `config.php`, `id_rsa`, robots.txt/sitemap yolları |
| **Pasif Secret Sızıntı Taraması** | HTTP yanıt gövdelerinde Regex tabanlı hassas veri analizi | **AWS Keys (`AKIA...`)**, **Google API Key**, **GitHub PAT**, **JWT**, **RSA Private Key**, **DB Credentials** |
| **Debug Modu Tespiti** | Web yanıtlarında framework hata ve stack trace tespiti | **Django Debug**, **Spring Whitelabel**, **Laravel Ignition/Whoops**, **PHP Stack Trace**, **ASP.NET Yellow Screen** |
| **Özyinelemeli (Recursive) Fuzzing**| Keşfedilen kök dizinlerin (`/admin`, `/api`, `/v1`, `/portal`, `/backup`) derinleştirilmesi | Alt dizinler, gizli API endpoint'leri ve yönetim fonksiyonları |
| **Genişletilmiş Pasif Denetim** | SSL/TLS sertifika & cipher analizi, HTTP Security Headers, CORS, GraphQL, SSH audit | Zayıf protokoller (SSLv3, TLS 1.0/1.1), eksik HSTS/CSP/X-Frame-Options, tehlikeli metotlar (`TRACE`, `PUT`) |
| **Nmap NSE Zafiyet Eşleme** | Servis/Port bazlı otomatik Nmap NSE script çalıştırma (`config.yaml`) | **SMB EternalBlue (`MS17-010`)**, **SSL Heartbleed**, **Apache RCE**, **RDP Encryption** vb. |
| **SOC Görsel Dashboard** | Glassmorphism temalı, filtrelemeli, responsive interaktif HTML raporu | Yönetici özeti, interaktif arama, çelişki kartları, zafiyet uyarıları |

---

## 🔄 3. Tam Otomatik Keşif Boru Hattı (Recon Pipeline)

SpecterRecon, tek bir hedef girdiğinde (Domain veya CIDR IP bloğu) aşağıdaki adımları birbirini besleyecek şekilde sırayla işletir:

```mermaid
flowchart TD
    A[🎯 Hedef: Domain / IP / CIDR / Import Dosyası] --> B{Girdi Türü & Parametreler}
    
    B -->|Domain| C[Modül 0: DNS Enumeration & AXFR & Takeover Testi]
    B -->|--nmap-xml| D[Seviye 1: Nmap XML İçe Aktarma]
    B -->|--masscan-json| E[Seviye 1: Masscan JSON İçe Aktarma]
    
    C --> F[Adım 1: Canlı Host Keşfi - ICMP/TCP/ARP]
    
    F --> G{Tarama Motoru Seçimi}
    G -->|balanced / stealth| H[SpecterRecon Native Go TCP Worker Pool]
    G -->|--use-masscan / aggressive| I[Masscan Subprocess Runner]
    
    E --> J[Açık Port Doğrulama Katmanı - TCP Handshake]
    I --> J
    
    J -->|✓ Handshake Başarılı| K[Verified=true Açık Portlar]
    J -->|❌ Handshake Başarısız| L[Conflict=true ⚠️ Çelişkili Portlar]
    
    H --> K
    D --> K
    
    K --> M[Adım 3: Derin Servis & OS Fingerprinting]
    M --> N[WAF & Favicon MMH3 & SMB2/LDAP/MSSQL/WinRM/RDP Probları]
    
    N --> O{NSE Zafiyet Taraması? --use-nmap-nse}
    O -->|Evet| P[Adım 3.5: config.yaml Haritalı Nmap NSE Taraması]
    O -->|Hayır| Q[Genişletilmiş Pasif Denetim - SSL/HTTP/SSH]
    P --> Q
    
    Q --> R[Adım 4: Catch-All Filtreli & Sızıntı Taramalı Akıllı Web Fuzzing]
    R --> R2[Özyinelemeli / Recursive Dizin Derinleştirme]
    R2 --> S[Adım 5: Raporlama - summary.txt & report.html]
    L --> S
```

---

## 🎯 4. Tarama Profilleri (`--profile`)

Tek bir bayrakla taramanın agresiflik, hız, gizlilik ve harici araç kullanım seviyesini ayarlayabilirsiniz:

| Profil | Motor | Eşzamanlılık (Worker) | İstek Gecikmesi | NSE Zafiyet Taraması | Wordlist Kapsamı | Kullanım Senaryosu |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`balanced`** *(Varsayılan)* | Go Native TCP | 50 Worker | 0 ms | Kapalı | Balanced (`common.txt` + Embedded) | Günlük taramalar, stabil ve güvenilir genel keşif. |
| **`aggressive`** | Masscan + Go Handshake | 100+ Worker | 0 ms | **Açık** (Otomatik) | Full (`SecLists Raft` + Embedded) | Geniş IP blokları, CTF ve tam yetkili kapsamlı sızma testleri. |
| **`stealth`** | Go Native TCP | 20 Worker | 100 ms (Adaptive) | Kapalı | Quick (Gecikmeli İstekler) | IDS/WAF alarmlarından kaçınarak yapılan sessiz keşifler. |

---

## 🌐 5. DNS & Altyapı Güvenlik Analizi Motoru

SpecterRecon, hedef domain için standart çözümlemenin ötesine geçerek kritik güvenlik denetimleri gerçekleştirir:

1. **DNS Zone Transfer (AXFR) Denetimi:**
   - Keşfedilen tüm Name Server'lar (NS) üzerine doğrudan TCP port 53 üzerinden ham DNS AXFR paketleri gönderir.
   - Eğer DNS sunucusunda Zone Transfer kısıtlaması yoksa, tüm alt alan adlarını ve IP adreslerini tek adımda dökerek `🚨 KRİTİK GÜVENLİK AÇIĞI` olarak alarm verir.
2. **Wildcard DNS Tespiti & Sahte Subdomain Filtreleme:**
   - Subdomain brute-force başlamadan önce `specter-recon-rnd-<uuid>.domain.com` şeklinde rastgele bir sorgu atar.
   - Eğer alan adı tüm sorgulara sabit bir IP dönüyorsa (Wildcard DNS), bu IP adresini kaydeder ve brute-force sırasında oluşan sahte subdomain fırtınasını tamamen eler.
3. **Subdomain Takeover (Alt Alan Adı Devralma) Analizi:**
   - CNAME kayıtlarını inceleyerek 25+ popüler bulut servis sağlayıcısı ile eşleştirir:
   - *GitHub Pages, AWS S3 / CloudFront, Heroku, Azure App Service / Traffic Manager, Ghost, Surge.sh, Shopify, Bitbucket, Pantheon, Readme.io, Zendesk, HelpScout, WPEngine, Firebase, Webflow, Vercel, Netlify.*
4. **Active Directory SRV & Ters DNS (PTR) Çözümleme:**
   - `_ldap._tcp`, `_kerberos._tcp`, `_kpasswd._tcp`, `_gc._tcp`, `_autodiscover._tcp`, `_sip._tls` sorgularıyla Active Directory Domain Controller'ları, Exchange sunucularını ve VoIP altyapılarını tespit eder.

---

## 🔬 6. Derin Servis & İşletim Sistemi (OS) Tespit Motoru

Körlemesine port kontrolü yerine servislere özel ikili (binary) protokol probları gönderilir:

* **SMB2 NTLMSSP Fingerprint (Port 445/139):**
  - Kimlik doğrulamaya gerek kalmadan NTLMSSP Type 2 Challenge paketinden Windows OS Major/Minor versiyonu, Build numarası (örn: `Build 9600 ➔ Windows Server 2012 R2`, `Build 17763 ➔ Windows Server 2019`, `Build 20348 ➔ Windows Server 2022`), NetBIOS Bilgisayar Adı, Active Directory Domain ve Forest bilgileri çıkarılır.
* **LDAP Anonymous RootDSE (Port 389/636):**
  - ASN.1 formatında kimliksiz RootDSE sorgusu atılarak `domainControllerFunctionality` (Level 6 = 2012 R2, Level 7 = 2016/2019/2022/2025), Domain FQDN ve DefaultNamingContext bilgileri elde edilir.
* **MSSQL TDS 7.x Pre-Login (Port 1433):**
  - TDS Pre-Login handshake byte dizisi gönderilerek SQL Server'ın ana sürümü (2022, 2019, 2017, 2016, 2014, 2012 vb.) ve tam build numarası (`v15.0.2000`) çözümlenir.
* **WinRM / WSMAN SOAP Identify (Port 5985/5986):**
  - `/wsman` endpoint'ine SOAP `Identify` isteği gönderilerek sunucu OS Build'i ve WS-Management protokol versiyonu (`Stack 3.0`) elde edilir.
* **RDP TLS Müzakeresi (Port 3389):**
  - X.224 Connection Request ardından TLS/NLA müzakeresi yapılarak sunucu sertifika CommonName (CN) ve FQDN'i alınır.
* **VNC RFB Handshake (Port 5900):**
  - RFB protokol sürümü (`RFB 005.000` / `003.008`) müzakere edilerek tespit edilir.
* **Fortinet Single Sign-On / FSSO (Port 8000):**
  - Fortinet kimlik doğrulama ajanı ve tam versiyonu (`FSSO v5.0.0319`) yakalanır.
* **Favicon MurmurHash3 (MMH3):**
  - Shodan uyumlu 32-bit MMH3 algoritması ile Spring Boot (`116323821`), Jenkins (`81586312`), phpMyAdmin, Grafana, WordPress, VMware vCenter vb. sistemler anında tanınır.
* **WAF & CDN Tespiti:**
  - Akamai (`AkamaiGHost`), Cloudflare, AWS CloudFront, Imperva, F5 BIG-IP, Sucuri tespit edilir ve `Host` header'ı sunucu adına eşitlenerek 400 Bad Request engelleri aşılır.

---

## 📂 7. Akıllı Web Fuzzing, Sızıntı Taraması & Özyinelemeli Keşif

1. **Catch-All Baseline & Soft-404 Koruması:**
   - Fuzzing başlamadan önce `/specter-fp-check-xyz-123` gibi var olmayan 3 yol sorgulanarak baseline profili oluşturulur.
   - Wildcard 301/302/403 yanıtları otomatik elenir; aynı (status:boyut) çifti 15 defadan fazla tekrar ederse frekans kümeleme filtresi devreye girer.
2. **Pasif Secret & Kredansiyel Sızıntı Taraması (Secret Leak Scanner):**
   - Dönen 200 OK yanıtlarının gövdeleri otomatik olarak taranır:
     - 🔑 **AWS Access Key ID:** `AKIA...`
     - 🔑 **Google API Keys:** `AIza...`
     - 🔑 **GitHub PAT Tokens:** `ghp_...`
     - 🔑 **Slack Webhooks:** `https://hooks.slack.com/services/T...`
     - 🔑 **JWT Token'lar:** `eyJ...`
     - 🔑 **Özel Anahtarlar:** `-----BEGIN PRIVATE KEY-----` (RSA/SSH)
     - 🔑 **Veritabanı Bağlantıları:** `postgres://`, `mysql://`, `mongodb://`, `redis://`
3. **Debug Modu ve Hata Sayfası Tespiti:**
   - Django Debug Mode (Settings/Stack Trace), Spring Boot Whitelabel, Laravel Ignition (Whoops), PHP Fatal Error Stack Trace ve ASP.NET Yellow Screen sayfaları otomatik olarak işaretlenir.
4. **Özyinelemeli (Recursive) Dizin Keşfi:**
   - Keşfedilen `/admin`, `/api`, `/v1`, `/portal`, `/dev`, `/backup`, `/app` gibi kök dizinler otomatik olarak ikinci aşama alt dizin fuzzing'ine tabi tutulur.
5. **Dinamik Teknoloji Mutasyonu:**
   - IIS tespit edilirse: `.aspx`, `.asp`, `.axd`, `.ashx`, `.config`, `trace.axd`, `elmah.axd` otomatik türetilir.
   - PHP tespit edilirse: `.php`, `.phtml`, `.php.bak`, `config.php`, `wp-config.php` otomatik türetilir.
   - Spring Boot tespit edilirse: `/actuator`, `/actuator/health`, `/actuator/env`, `/swagger-ui.html` dahil edilir.

---

## 🛡️ 8. Port Doğrulama ve Çelişki Çözümleme Katmanı (Conflict Resolution)

Masscan gibi durumsuz (stateless) SYN tarayıcılar, önlerindeki SYN-Proxy veya durumsuz güvenlik duvarları nedeniyle kapalı portlara da SYN-ACK üretebilir.

SpecterRecon bu sorunu **İki Aşamalı Doğrulama** ile çözer:
1. Masscan çıktısındaki her porta hızlı native Go TCP Connect handshake'i denenir.
2. Port erişilebilir ise `Source: "masscan"`, `Verified: true` olarak işaretlenir.
3. Bağlantı reddedilir veya zaman aşımına uğrarsa veri **asla silinmez**; `Conflict: true` olarak etiketlenir ve HTML raporda **`⚠️ Çelişkili Port Bulguları (Conflicting Ports)`** bölümünde şeffaf olarak listelenir.

---

## 💻 9. İnteraktif Konsol Modu (Readline / Metasploit Style)

SpecterRecon hiçbir parametre verilmeden çalıştırıldığında veya `shell` komutu girildiğinde **GNU Readline tabanlı interaktif konsola** geçer:

```text
specter-recon > scan example.com --authorized
specter-recon > fullscan 10.0.0.100 --authorized
specter-recon > dirfuzz http://10.0.0.100 --service iis --authorized
specter-recon > ssl example.com:443 --authorized
specter-recon > report -t "Müşteri Denetimi" --authorized
specter-recon > help
specter-recon > exit
```

**Konsol Özellikleri:**
* `↑` / `↓` tuşları ile geçmiş komutlar arasında gezinme.
* `←` / `→` tuşları ile satır içinde imleç kaydırma ve düzenleme.
* `TAB` tuşu ile komut ve alt komutları otomatik tamamlama.
* `Ctrl+C` ile çalışan komutu / satırı kesme (oturumu kapatmaz).
* `Ctrl+D` veya `exit` ile güvenli çıkış.
* Hatalı bayrak girildiğinde ekranı kaplayan gereksiz usage çıktısı vermez (`SilenceUsage: true`).

---

## 📁 10. Proje Dizin Yapısı

```
SpecterRecon/
├── main.go                       # Uygulama ana giriş noktası
├── go.mod                        # Go modül bağımlılık tanımı (Go 1.21+)
├── config.yaml                   # Tarama, zaman aşımı ve NSE script haritaları
├── LICENSE                       # MIT Lisansı
├── CONTRIBUTING.md               # Katkı ve geliştirme kuralları
├── README.md                     # Proje ana dokümantasyonu
│
├── cmd/                          # Cobra CLI Komut Katmanı
│   ├── root.go                   # Kök komut, global bayraklar ve --help motoru
│   ├── scan.go                   # Ana recon pipeline komutu (Profiller & İçe Aktarma)
│   ├── fullscan.go               # scan --extended kısayolu
│   ├── shell.go                  # Readline destekli interaktif konsol modu
│   ├── dns.go                    # Bağımsız DNS & Subdomain tarama komutu
│   ├── discover.go               # Bağımsız Host keşif komutu
│   ├── portscan.go               # Bağımsız Port tarama komutu
│   ├── banner.go                 # Bağımsız Banner grabbing & versiyon komutu
│   ├── dirfuzz.go                # Bağımsız Web Dizin fuzzer komutu
│   ├── ssl.go                    # Bağımsız SSL/TLS audit komutu
│   └── report.go                 # Rapor üretim komutu
│
├── core/                         # Çekirdek Veri Modelleri ve Yardımcılar
│   ├── models.go                 # Struct şemaları (DNSFinding, PortInfo, ServiceDetail vb.)
│   ├── storage.go                # JSON/TXT kaydetme/okuma ve özet rapor yazıcısı
│   └── logger.go                 # PTerm konsol logları, tablolar ve renkli çıktılar
│
├── modules/                      # Keşif ve Güvenlik Motorları
│   ├── dns_enum.go               # DNS çözümleme, AXFR, Wildcard & Takeover motoru
│   ├── discovery.go              # ARP, ICMP ve TCP SYN ping ile canlı host keşfi
│   ├── portscan.go               # Goroutine Worker Pool TCP Connect tarayıcısı
│   ├── port_verify.go            # Açık Port Doğrulama & Çelişki Çözümleme Katmanı
│   ├── service_probes.go         # Derin binary problar (SMB2, LDAP, TDS, WinRM, RDP, VNC)
│   ├── banner.go                 # Wappalyzer Regex, WAF Tespiti & Servis Ayrıştırıcı
│   ├── favicon.go                # Favicon Murmur3 (MMH3) 32-bit Hash Motoru
│   ├── dirfuzz.go                # Catch-All Filtreli, Secret Sızıntı Taramalı Web Fuzzer
│   ├── ssl_tls.go                # SSL/TLS sertifika & zayıf protokol denetleyici
│   ├── http_audit.go             # HTTP Security Headers, CORS, GraphQL ve yöntem denetleyici
│   ├── ssh_audit.go              # SSH algoritma, banner ve root login denetleyici
│   ├── external_tools.go         # Masscan & Nmap NSE Subprocess Yöneticisi
│   ├── nmap_import.go            # Nmap XML (-oX) Ayrıştırıcı Motoru
│   ├── masscan_import.go         # Masscan JSON (-oJ) Ayrıştırıcı Motoru
│   ├── report.go                 # HTML Rapor oluşturucu motor
│   └── modules_test.go           # 30 adet kapsamlı Go birim testi (%100 PASS)
│
├── templates/
│   ├── templates.go              # Gömülü HTML rapor şablonu
│   └── report.html.tmpl          # Glassmorphism SOC HTML dashboard şablonu
│
└── wordlists/                    # Gömülü Wordlistler (Zero-Dependency)
    ├── embedded.go               # //go:embed ile derlenen hazır servis wordlistleri
    ├── common.txt                # Hızlı web dizin listesi
    ├── subdomains.txt            # Subdomain brute-force listesi
    ├── sensitive.txt             # Hassas dosya listesi (.env, .git, config vb.)
    ├── service_wordlist_map.yaml # Servis ➔ Wordlist eşleştirme haritası
    └── SecLists/                 # SecLists git submodule (Full mod)
```

---

## 📥 11. Kurulum ve Derleme

### 1. Projeyi Klonlama ve Derleme
```bash
# Repoyu klonlayın:
git clone https://github.com/1Ssalih/SpecterRecon.git
cd SpecterRecon

# Bağımlılıkları indirin:
go mod download

# Linux için derleyin ve yerel dizine yükleyin:
go build -trimpath -ldflags="-s -w" -o specter-recon main.go
cp -f specter-recon ~/.local/bin/specter-recon

# Windows için çapraz derleme (.exe):
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o specter-recon.exe main.go
```

### 2. Linux Raw Socket Yetkisi (Masscan Kullanımı İçin)
Linux üzerinde root olmadan Masscan raw socket paketleri göndermek için:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip specter-recon
```

---

## 🚀 12. Kapsamlı Komut Satırı Kullanım Kılavuzu (CLI Examples)

### 1. İnteraktif Konsol Modu (Parametresiz Çalıştırma)
```bash
specter-recon
```

### 2. Tam Boru Hattı Keşif Taraması (`scan` & `fullscan`)
```bash
# Temel boru hattı taraması (DNS + Host + Port + Banner + Web Fuzzing)
specter-recon scan example.com --authorized

# Subdomain brute-force ve tüm pasif denetimlerle (SSL/HTTP/SSH) tam tarama
specter-recon fullscan example.com --subdomains --authorized

# Saldırgan Profil (Masscan + Nmap NSE + SecLists Full Dizin Fuzzing)
specter-recon scan 10.0.0.0/16 --profile aggressive --authorized

# Gizli / Stealth Profil (20 Worker, 100ms gecikmeli istekler)
specter-recon scan example.com --profile stealth -d 100 --authorized

# Tüm 65535 TCP portunu 200 eşzamanlı worker ile tara
specter-recon scan 10.0.0.100 -p 1-65535 -t 200 --authorized

# Önceden alınmış Nmap XML çıktısını içe aktarma
specter-recon scan --nmap-xml nmap_results.xml --authorized

# Önceden alınmış Masscan JSON çıktısını içe aktarma ve TCP handshake ile doğrulama
specter-recon scan --masscan-json masscan_out.json --authorized
```

### 3. Bağımsız Modül Komutları
```bash
# 📡 DNS Enumeration (AXFR Zone Transfer, Wildcard & Subdomain Takeover Testi)
specter-recon dns example.com --subdomains -t 100 --authorized

# 🔍 Canlı Host Keşfi (ICMP/TCP Ping)
specter-recon discover 192.168.1.0/24 --authorized

# 🔌 Yüksek Hızlı Port Taraması
specter-recon portscan 10.0.0.100 -p 1-65535 -t 200 --authorized

# 🏷️ Banner Grabbing & Derin Protokol Tespiti
specter-recon banner -i output/ports.json -o output/services.json --authorized

# 📂 Akıllı Web Dizin Fuzzing (Catch-All Baseline + Secret Leak Scanner)
specter-recon dirfuzz http://10.0.0.100:80 --service iis --authorized
specter-recon dirfuzz https://example.com --service wordpress --wordlist-size full --authorized

# 🔒 SSL/TLS Sertifika & Güvenlik Başlıkları Audit
specter-recon ssl example.com:443 --authorized

# 📊 Mevcut Çıktılardan HTML Dashboard Raporu Üretme
specter-recon report -t "Kurumsal Güvenlik Denetim Raporu" --authorized
```

---

## ⚙️ 13. Yapılandırma (`config.yaml`)

`config.yaml` üzerinden Nmap NSE eşleştirmelerini, zaman aşımlarını ve fuzzer davranışını özelleştirebilirsiniz:

```yaml
# Nmap Scripting Engine (NSE) Otomatik Script Eşleştirmeleri
nse_mappings:
  "445":
    - smb-vuln-ms17-010
    - smb-os-discovery
  "443":
    - ssl-heartbleed
    - ssl-cert
    - ssl-enum-ciphers
  "80":
    - http-vuln-cve2021-41773
    - http-methods
  "22":
    - ssh-auth-methods
  "3389":
    - rdp-enum-encryption
  "http":
    - http-vuln-cve2021-41773
    - http-methods
  "smb":
    - smb-vuln-ms17-010

# Web Fuzzing Yapılandırması
dirfuzz:
  wordlist_path: "wordlists/common.txt"
  sensitive_wordlist_path: "wordlists/sensitive.txt"
  concurrency: 30
  timeout: 4.0
  status_codes_of_interest: [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
```

---

## 📊 14. SOC Raporlama ve Çıktı Formatları

Tarama sonuçları `output/` dizininde otomatik oluşturulur:

1. **`output/report.html` (Görsel SOC Dashboard):** Glassmorphism CSS teması, WAF rozetleri, Nmap NSE Zafiyet Bulguları kartı, Secret Sızıntıları tablosu ve Masscan Çelişkili Portlar tablosu içeren interaktif HTML raporu.
2. **`output/summary.txt` (Konsolide Metin Özeti):** Tüm host, port, servis, tam versiyon, güven skoru ve zafiyet özetini içeren yönetici özeti.
3. **`output/services.json`:** Her servis için kanıt dizisi (`evidence`), güven skoru (`confidence`), WAF bilgisi ve TLS sertifika detaylarını içeren yapılandırılmış JSON verisi.
4. **`output/findings.txt`:** Catch-All sahte bulgularından arındırılmış, durum kodları ve hassas dosya etiketleri içeren web bulguları.
5. **`output/ip_list.json`:** DNS, SRV ve Ters DNS sorgularından elde edilen tüm doğrulanmış IP listesi.

---

## ⚖️ 15. Yasal Uyarı ve Lisans

> ⚠️ **YASAL UYARI:**  
> **SpecterRecon**, yalnızca **yasal olarak izin alınmış güvenlik denetimleri**, sızma testleri, kurum içi denetimler ve eğitim lab ortamları için geliştirilmiştir. Yetkisiz sistemlere karşı izin almadan tarama yapmak yasalara (TCK Madde 243/244, 5651 Sayılı Kanun, CFAA vb.) aykırıdır ve ağır cezai sorumluluk doğurur.  
> Geliştirici, aracın kötüye kullanımından doğabilecek hiçbir zarardan sorumlu tutulamaz.

### Lisans
Bu proje **[MIT Lisansı](LICENSE)** altında lisanslanmıştır.

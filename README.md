<div align="center">

# ⚡ SpecterRecon (v0.8.0)
### *Yüksek Performanslı, Bağlam Duyarlı ve Hibrit Ağ Keşif & Zafiyet Görünürlük Motoru*

[![Go Version](https://img.shields.io/badge/Go-1.26.0+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![CI Status](https://img.shields.io/badge/CI-GitHub_Actions-blue?style=for-the-badge&logo=githubactions&logoColor=white)](.github/workflows/ci.yml)
[![Version](https://img.shields.io/badge/Release-v0.8.0_Enterprise-00f2fe?style=for-the-badge&logo=semver&logoColor=black)](#)
[![Fuzzing](https://img.shields.io/badge/Fuzzing-Status--Agnostic_Catch--All_%2B_Secret_Scanner-brightgreen?style=for-the-badge&logo=shield&logoColor=white)](#)
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
  <b>SpecterRecon</b>; sızma testi uzmanları, kırmızı takım (Red Team) operatörleri, siber güvenlik araştırmacıları ve SOC analistleri için <b>Go (Golang 1.26+)</b> ile sıfırdan tasarlanmış modern bir keşif ve zafiyet görünürlük platformudur.<br>
  <b>DNS Altyapı Güvenliği (AXFR Zone Transfer, Wildcard DNS, 25+ Sağlayıcı Subdomain Takeover), Canlı Host Keşfi, Hibrit Port Tarama (Native Goroutine / Masscan), İki Aşamalı Port Doğrulama ve Çelişki Çözümleme (Conflict Resolution), Kimliksiz Derin Protokol & İşletim Sistemi Parmak İzi (SMB2 NTLMSSP Build, LDAP RootDSE, MSSQL TDS 7.x, WinRM SOAP, RDP TLS, VNC RFB, Fortinet FSSO), WAF/CDN Tespiti (Akamai, Cloudflare, AWS), Status-Agnostic Catch-All & Soft-404 Korumalı Akıllı Web Fuzzing, Pasif Kredansiyel & API Key Sızıntı Taraması, Nmap NSE Zafiyet Eşleme ve Glassmorphism Temalı SOC Dashboard Raporlama</b> süreçlerini tek bir bağımsız ikili dosyada (zero-dependency binary) birleştirir.
</p>

---

</div>

## 📌 İçindekiler

- [🎯 1. Temel Felsefe ve Mimari Prensipler](#-1-temel-felsefe-ve-mimari-prensipler)
- [⚡ 2. Modüler Mimari ve Yetenek Matrisi](#-2-modüler-mimari-ve-yetenek-matrisi)
- [🔄 3. Derinlemesine Keşif Boru Hattı (Recon Pipeline Architecture)](#-3-derinlemesine-keşif-boru-hattı-recon-pipeline-architecture)
- [🎯 4. Tarama Profilleri (`--profile`)](#-4-tarama-profilleri---profile)
- [🌐 5. DNS & Altyapı Güvenlik Analiz Motoru](#-5-dns--altyapı-güvenlik-analiz-motoru)
- [🔬 6. Derin Servis & İşletim Sistemi (OS) Tespit Motoru](#-6-derin-servis--i̇şletim-sistemi-os-tespit-motoru)
- [📂 7. Akıllı Web Fuzzing, Catch-All Filtresi & Sızıntı Taraması](#-7-akıllı-web-fuzzing-catch-all-filtresi--sızıntı-taraması)
- [🛡️ 8. Port Doğrulama ve Çelişki Çözümleme Katmanı (Conflict Resolution)](#-8-port-doğrulama-ve-çelişki-çözümleme-katmanı-conflict-resolution)
- [💻 9. İnteraktif Konsol Modu (Readline / REPL Interface)](#-9-i̇nteraktif-konsol-modu-readline--repl-interface)
- [📁 10. Proje Dizin Yapısı](#-10-proje-dizin-yapısı)
- [📥 11. İşletim Sistemlerine Göre Ayrıntılı Kurulum Kılavuzu](#-11-i̇şletim-sistemlerine-göre-ayrıntılı-kurulum-kılavuzu)
  - [🐧 Linux (Ubuntu, Debian, Kali Linux, Parrot OS)](#-linux-ubuntu-debian-kali-linux-parrot-os)
  - [🏹 Linux (Arch Linux, Manjaro, BlackArch)](#-linux-arch-linux-manjaro-blackarch)
  - [🎩 Linux (Fedora, RHEL, Rocky Linux, CentOS)](#-linux-fedora-rhel-rocky-linux-centos)
  - [🍎 macOS (Apple Silicon M1/M2/M3/M4 & Intel x86_64)](#-macos-apple-silicon-m1m2m3m4--intel-x86_64)
  - [🪟 Windows (Windows 10, 11 & Windows Server)](#-windows-windows-10-11--windows-server)
  - [🐳 Docker / Container ile Çalıştırma](#-docker--container-ile-çalıştırma)
- [🚀 12. Kapsamlı Komut Satırı Kullanım Kılavuzu (CLI Reference & Examples)](#-12-kapsamlı-komut-satırı-kullanım-kılavuzu-cli-reference--examples)
- [⚙️ 13. Yapılandırma Dosyası (`config.yaml`)](#️-13-yapılandırma-dosyası-configyaml)
- [📊 14. SOC Raporlama ve Çıktı Formatları](#-14-soc-raporlama-ve-çıktı-formatları)
- [📋 15. Günlük Tutma, Denetim İzi (Audit Log) & Uyumluluk](#-15-günlük-tutma-denetim-izi-audit-log--uyumluluk)
- [⚖️ 16. Yasal Uyarı ve Lisans](#️-16-yasal-uyarı-ve-lisans)

---

## 🎯 1. Temel Felsefe ve Mimari Prensipler

Geleneksel keşif süreçlerinde güvenlik uzmanları onlarca farklı aracı (amass, subfinder, nmap, masscan, httpx, ffuf, testssl, nuceli vb.) peş peşe çalıştırır. Bu durum şu kronik problemlere yol açar:
1. **Bağlam Kopukluğu (Context Loss):** Bir aracın bulduğu bilgi (örneğin WAF varlığı veya IIS servisi) bir sonraki fuzzer aracına aktarılmaz; fuzzer körlemesine standart PHP wordlist dener.
2. **Soket Darboğazı ve SYN-Flood Filtreleri:** Yüksek eşzamanlılıkla kontrolsüz gönderilen SYN paketleri durum bilgili (stateful) kurumsal firewall'lar tarafından engellenir ve canlı portlar "kapalı" veya "filtrelenmiş" olarak raporlanır.
3. **Catch-All ve Yönlendirme Fırtınası (False-Positive Flood):** Hedef web sunucusu bilinmeyen tüm isteklere `302 Found ➔ /Login.aspx?ReturnUrl=...` veya `401 Unauthorized` dönüyorsa, standart fuzzer'lar binlerce sahte pozitif "Kritik Dosya Bulundu" uyarısı üretir.

**SpecterRecon'un Çözüm İlkeleri:**
* **Sıfır Dış Bağımlılık (Zero-Dependency Architecture):** Sistemde Masscan veya Nmap olmasa dahi, Go'nun yerel Goroutine Worker Pool motoru ve gömülü wordlist'leri (`//go:embed`) sayesinde tek bir binary halinde eksiksiz çalışır.
* **Akıllı Bağlam Aktarımı (Context-Aware Pipeline):** Port taramasında tespit edilen servisler otomatik olarak Banner Grabbing modülüne, oradan elde edilen web teknolojisi ve WAF bilgisi ise doğrudan Dizin Fuzzing ve NSE motoruna aktarılır.
* **Status-Agnostic Catch-All Baseline Koruması:** Fuzzing öncesinde hedef sisteme 5 farklı formatta test probu gönderilir; dönen durum kodları (200, 302, 401, 403, 500), yanıt gövdesi FNV-1a snippet hash'i ve yönlendirme hedefleri kümelenerek baseline oluşturulur. Fuzzing sırasında dinamik frekans filtresi ile sahte bulgular anında elenir.
* **Kimliksiz Derin Keşif (Unauthenticated Deep Recon):** Windows/Active Directory ormanlarında kimlik doğrulamaya gerek duymadan SMB2 NTLMSSP Challenge, LDAP RootDSE ASN.1, MSSQL TDS 7.x Pre-Login ve RDP TLS paketleri ile tam işletim sistemi build'i, AD domain adı ve sunucu sertifikaları çekilir.
* **İki Aşamalı Doğrulama (Conflict Resolution):** Masscan ile bulunan her port native Go TCP handshake'i ile teyit edilir; firewall kaynaklı yalancı pozitifler şeffaf biçimde "Çelişkili Portlar" kategorisine ayrılır.

---

## ⚡ 2. Modüler Mimari ve Yetenek Matrisi

| Modül | Protokol / Algoritma | Açıklama ve Tespit Edilen Kritik Bulgular |
| :--- | :--- | :--- |
| **DNS Güvenlik Motoru** | DNS RFC 1035 / TCP 53 AXFR / CNAME Resolver | **DNS Zone Transfer (AXFR) Açığı**, **Wildcard DNS Tespiti**, **Subdomain Takeover (25+ Bulut Sağlayıcı)**, Active Directory SRV (`_ldap`, `_kerberos`), Ters DNS (PTR). |
| **Canlı Host Keşfi** | ICMP Echo, ARP, TCP Probe (`TCP_OPEN` / `TCP_RST`) | Ağ topolojisi haritalama, canlı IP listesi, milisaniye hassasiyetli RTT ölçümü. |
| **Hibrit Port Tarayıcı** | Native Go TCP Connect Worker Pool + Masscan Subprocess | 1-65535 arası yüksek hızlı TCP taraması, otomatik yedek tarama (fallback retry) ile SYN-flood engellerini aşma. |
| **Port Teyit & Çelişki Katmanı**| İki Aşamalı TCP 3-Way Handshake Doğrulaması | Masscan ve harici araçların ürettiği sahte açık portları teyit eder; çelişkileri `Conflicting Ports` tablosunda belgeler. |
| **SMB2/3 OS Fingerprint** | NTLMSSP Type 2 Challenge Parser | Windows Server Build (`2012 R2 / 2016 / 2019 / 2022 / 2025`), NetBIOS Bilgisayar Adı, Active Directory Domain & Forest FQDN. |
| **LDAP RootDSE Motoru** | ASN.1 Lightweight Directory Access Protocol | AD Domain Controller Fonksiyonel Seviyesi (`FuncLevel 6=2012R2, 7=2016+`), DefaultNamingContext, Domain FQDN. |
| **MSSQL TDS Motoru** | TDS 7.x Pre-Login Handshake Byte Stream | SQL Server ana sürümü ve tam derleme numarası (örn: `SQL Server 2022 v16.0.1000`). |
| **WinRM / WSMAN Motoru** | SOAP Identify over HTTP/HTTPS (`/wsman`) | Windows OS Build, WS-Management protokol sürümü (`Stack 3.0`). |
| **RDP & VNC Motoru** | X.224 Connection Request + TLS/NLA / RFB Handshake | RDP TLS Sertifika CN/FQDN bilgileri, VNC RFB Protokol sürümü (`RFB 003.008` / `005.000`). |
| **Favicon MMH3 Motoru** | Shodan %100 Uyumlu 32-bit MurmurHash3 | Spring Boot (`116323821`), Jenkins (`81586312`), phpMyAdmin, Grafana, WordPress, VMware vCenter vb. |
| **WAF & CDN Tespiti** | HTTP Header & Body Analizi | Akamai (`AkamaiGHost`), Cloudflare, AWS CloudFront, Imperva, F5 BIG-IP, Sucuri tespiti; dinamik Host header optimizasyonu. |
| **Catch-All Web Fuzzing** | Multi-Probe Baseline & FNV-1a Body Snippet Hash | 302 Dynamic Query, 401 Unauthorized, 403 Forbidden, 500 Error ve 200 Soft-404 filtreleme; SecLists & Embedded wordlist. |
| **Pasif Secret Sızıntı Taraması**| Regex Pattern Matching on HTTP Bodies | **AWS Access Key (`AKIA...`)**, **Google API Key**, **GitHub PAT**, **Slack Webhook**, **JWT**, **RSA/SSH Private Key**, **DB URI**. |
| **Debug Sayfası Tespiti** | Framework Error Signature Matching | **Django Debug (Settings/Stack)**, **Spring Boot Whitelabel**, **Laravel Ignition (Whoops)**, **PHP Stack Trace**, **ASP.NET Yellow Screen**. |
| **Özyinelemeli (Recursive) Fuzz**| Multi-Threaded Depth-First Fuzzing | Keşfedilen kök dizinlerin (`/admin/`, `/api/`, `/v1/`, `/portal/`, `/backup/`, `/dev/`) derinleştirilmesi. |
| **Genişletilmiş Pasif Denetim**| TLS Cipher/Cert Suite, HTTP Security Headers, CORS, SSH | Zayıf protokoller (SSLv3, TLS 1.0/1.1), eksik HSTS/CSP/X-Frame-Options, tehlikeli metotlar (`TRACE`, `PUT`), SSH zayıf algoritmalar. |
| **Nmap NSE Zafiyet Eşleme** | Otomatik Servis-NSE Haritalama (`config.yaml`) | **SMB EternalBlue (`MS17-010`)**, **SSL Heartbleed**, **Apache RCE**, **RDP Encryption** zafiyet taramaları. |
| **SOC Raporlama Dashboard'u** | Glassmorphism Responsive HTML5 + JSON/TXT | İnteraktif arama, filtreleme, zafiyet kartları, çelişki tabloları, tam denetim izi (`audit.log`). |

---

## 🔄 3. Derinlemesine Keşif Boru Hattı (Recon Pipeline Architecture)

SpecterRecon, hedefe yönelik girdiyi (Domain, IP, CIDR veya dosya) adım adım işleyen tam senkronize bir boru hattına sahiptir:

```mermaid
flowchart TD
    Start[🎯 Hedef Girdisi: Domain / IP / CIDR / Nmap-XML / Masscan-JSON] --> Decision{Girdi Türü Nedir?}
    
    %% DNS ve İçe Aktarma
    Decision -->|Domain| Step0[Modül 0: DNS Enumeration & Altyapı Güvenliği]
    Decision -->|--nmap-xml| ImportNmap[Nmap XML -oX İçe Aktarma]
    Decision -->|--masscan-json| ImportMasscan[Masscan JSON -oJ İçe Aktarma]
    Decision -->|IP / CIDR| Step1[Adım 1: Canlı Host Keşfi - ICMP/TCP SYN]
    
    Step0 -->|AXFR / Subdomain / Wildcard / AD SRV / PTR| Step1
    
    %% Port Tarama
    Step1 --> EngineSelect{Port Tarama Motoru}
    EngineSelect -->|balanced / stealth| NativeScan[Go Native TCP Goroutine Pool]
    EngineSelect -->|--use-masscan / aggressive| MasscanRun[Masscan Subprocess Runner]
    
    %% Port Teyit ve Çelişki
    MasscanRun --> VerifyLayer[İki Aşamalı Açık Port Doğrulama]
    ImportMasscan --> VerifyLayer
    
    VerifyLayer -->|✓ Handshake Başarılı| VerifiedPorts[Doğrulanmış Açık Portlar]
    VerifyLayer -->|❌ Handshake Başarısız| ConflictPorts[⚠️ Çelişkili Portlar Listesi]
    
    NativeScan --> VerifiedPorts
    ImportNmap --> VerifiedPorts
    
    %% Banner & Derin Fingerprint
    VerifiedPorts --> Step3[Adım 3: Derin Servis & İşletim Sistemi Fingerprinting]
    Step3 --> DeepProbes[SMB2 NTLMSSP + LDAP RootDSE + MSSQL TDS + WinRM + RDP + Favicon MMH3]
    DeepProbes --> WAFDetect[WAF / CDN Tespiti & Host Header Ayarlaması]
    
    %% NSE ve Pasif Modüller
    WAFDetect --> NSECheck{Nmap NSE Taraması? --use-nmap-nse}
    NSECheck -->|Evet| NSERun[Adım 3.5: config.yaml Haritalı Nmap NSE Taraması]
    NSECheck -->|Hayır| ExtendedPassive[Genişletilmiş Pasif Denetim: SSL/TLS + HTTP Headers + CORS + SSH]
    NSERun --> ExtendedPassive
    
    %% Web Fuzzing
    ExtendedPassive --> Step4[Adım 4: Akıllı Web Dizin & Dosya Fuzzing]
    Step4 --> BaselineProbe[Status-Agnostic Catch-All Baseline & FNV-1a Hash Analizi]
    BaselineProbe --> DynamicFuzz[Dinamik Frekans Filtreli Fuzzing & Pasif Secret Sızıntı Taraması]
    DynamicFuzz --> RecursiveFuzz[Özyinelemeli / Recursive Dizin Derinleştirme]
    
    %% Raporlama
    RecursiveFuzz --> Step5[Adım 5: Çok Formatlı SOC Raporlama]
    ConflictPorts --> Step5
    Step5 --> ReportOutput[report.html + summary.txt + services.json + findings.txt + audit.log]
```

---

## 🎯 4. Tarama Profilleri (`--profile`)

SpecterRecon, operasyonun türüne ve ağın durumuna göre 3 temel çalışma profili sunar:

| Profil | Motor | Eşzamanlılık (Worker) | İstek Gecikmesi (Delay) | NSE Taraması | Wordlist Kapsamı | İdeal Kullanım Alanı |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`balanced`** *(Varsayılan)* | Go Native TCP | 50 Worker | 0 ms | Kapalı | Quick/Balanced (`common.txt` + Embedded) | Günlük kurumsal pentestler, stabil ve gürültüsüz genel keşif. |
| **`aggressive`** | Masscan + Go Teyit | 100+ Worker | 0 ms | **Açık** (Otomatik) | Full (`SecLists Raft Medium` + Embedded) | Geniş IP blokları (/16, /24), CTF'ler ve tam yetkili kapsamlı sızma testleri. |
| **`stealth`** | Go Native TCP | 20 Worker | 100 ms (Adaptive) | Kapalı | Quick (Gecikmeli İstekler) | SOC/SIEM alarmlarından ve IDS/IPS engellemelerinden kaçınarak yapılan sessiz keşifler. |

---

## 🌐 5. DNS & Altyapı Güvenlik Analiz Motoru

Domain hedeflerinde standart DNS sorgularının ötesine geçilerek altyapı güvenliği denetlenir:

1. **DNS Zone Transfer (AXFR) Denetimi:**
   - Keşfedilen tüm Name Server'lar (NS) üzerine doğrudan TCP port 53 üzerinden ham AXFR sorguları gönderilir.
   - Sunucuda kısıtlama yoksa tüm alt alan adları tek adımda çekilir ve `🚨 KRİTİK GÜVENLİK AÇIĞI` olarak raporlanır.
2. **Wildcard DNS Tespiti & Sahte Subdomain Filtreleme:**
   - Subdomain brute-force başlamadan önce `specter-recon-rnd-<uuid>.domain.com` şeklinde rastgele bir sorgu atılır.
   - Eğer alan adı var olmayan tüm hostlara sabit bir IP dönüyorsa, bu IP kaydedilir ve brute-force sırasında oluşacak binlerce sahte subdomain anında elenir.
3. **Subdomain Takeover (Alt Alan Adı Devralma) Analizi:**
   - CNAME kayıtları 25+ popüler bulut sağlayıcısının (GitHub Pages, AWS S3/CloudFront, Heroku, Azure App Service, Ghost, Surge, Shopify, Bitbucket, Pantheon, Readme.io, Zendesk, HelpScout, WPEngine, Firebase, Webflow, Vercel, Netlify vb.) hata parmak izleri ile eşleştirilerek devralınabilir subdomainler tespit edilir.
4. **Active Directory SRV & Ters DNS (PTR) Çözümleme:**
   - `_ldap._tcp`, `_kerberos._tcp`, `_kpasswd._tcp`, `_gc._tcp`, `_autodiscover._tcp`, `_sip._tls` kayıtları sorgulanarak ortamdaki Domain Controller, Exchange ve VoIP sunucuları keşfedilir.

---

## 🔬 6. Derin Servis & İşletim Sistemi (OS) Tespit Motoru

Körlemesine port kontrolü yerine servislere özel ikili (binary) protokol probları gönderilir:

* **SMB2 NTLMSSP Fingerprint (Port 445/139):**
  - Kimlik doğrulamaya gerek kalmadan NTLMSSP Type 2 Challenge paketinden Windows OS Major/Minor versiyonu, Build numarası (`Build 9600 ➔ Windows Server 2012 R2`, `Build 17763 ➔ Windows Server 2019`, `Build 20348 ➔ Windows Server 2022`, `Build 26100 ➔ Windows Server 2025`), NetBIOS Bilgisayar Adı, Active Directory Domain ve Forest bilgileri çıkarılır.
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

## 📂 7. Akıllı Web Fuzzing, Catch-All Filtresi & Sızıntı Taraması

1. **Status-Agnostic Catch-All Baseline & FNV-1a Snippet Hash Koruması:**
   - Fuzzing başlamadan önce 5 farklı formatta test probu gönderilir (`specter-fp-check-...`, `.html`, `.aspx`, `.php`, `sub/index`).
   - Dönen yanıtlar kümelenerek baseline oluşturulur. Status kodundan bağımsız olarak (302 Login redirect, 401 Basic auth, 403 Forbidden, 500 Server error, 200 Soft-404) aynı imzayı taşıyan yanıtlar otomatik elenir.
   - **Dinamik Frekans Kümeleme:** Fuzzing sırasında aynı (status:boyut:hedef) kalıbı 5 defadan fazla tekrar ederse, runtime'da otomatik olarak Catch-All olarak işaretlenir ve önceki ilk 5 sahte bulgu da rapordan temizlenir.
   - **Kesin Kural:** 301/302 yönlendirmeleri ve Catch-All 401/403 yanıtları asla `[KRİTİK DOSYA]` olarak etiketlenmez.
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

## 💻 9. İnteraktif Konsol Modu (Readline / REPL Interface)

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
├── go.mod                        # Go modül bağımlılık tanımı (Go 1.26+)
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
│   └── modules_test.go           # Kapsamlı Go birim testleri (%100 PASS)
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

## 📥 11. İşletim Sistemlerine Göre Ayrıntılı Kurulum Kılavuzu

SpecterRecon, Go derleyicisinin yüklü olduğu tüm işletim sistemlerinde doğrudan kaynak koddan veya tek bir komutla derlenip çalıştırılabilir.

### 🐧 Linux (Ubuntu, Debian, Kali Linux, Parrot OS)

#### 1. Gereksinimlerin Yüklenmesi
```bash
sudo apt update
sudo apt install -y git golang-go libpcap-dev

# İsteğe bağlı harici hızlandırıcılar (Önerilir):
sudo apt install -y masscan nmap
```

#### 2. Repoyu İndirme ve Derleme
```bash
git clone https://github.com/1Ssalih/SpecterRecon.git
cd SpecterRecon

# Bağımlılıkları kontrol et ve indir
go mod download

# Optimize edilmiş bağımsız ikili (binary) üretimi
go build -trimpath -ldflags="-s -w" -o specter-recon main.go

# Sistem geneline taşıma
sudo mv specter-recon /usr/local/bin/
```

#### 3. Root Olmadan Raw Socket / Masscan Yetkisi Verme (Linux Linux Capabilities)
```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service=eip /usr/local/bin/specter-recon
```

---

### 🏹 Linux (Arch Linux, Manjaro, BlackArch)

```bash
sudo pacman -Syu --needed git go libpcap masscan nmap

git clone https://github.com/1Ssalih/SpecterRecon.git
cd SpecterRecon
go mod download
go build -trimpath -ldflags="-s -w" -o specter-recon main.go
sudo install -Dm755 specter-recon /usr/local/bin/specter-recon
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/specter-recon
```

---

### 🎩 Linux (Fedora, RHEL, Rocky Linux, CentOS)

```bash
sudo dnf install -y git golang libpcap-devel masscan nmap

git clone https://github.com/1Ssalih/SpecterRecon.git
cd SpecterRecon
go mod download
go build -trimpath -ldflags="-s -w" -o specter-recon main.go
sudo cp specter-recon /usr/local/bin/
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/specter-recon
```

---

### 🍎 macOS (Apple Silicon M1/M2/M3/M4 & Intel x86_64)

#### 1. Homebrew ile Paketlerin Yüklenmesi
```bash
brew update
brew install git go masscan nmap
```

#### 2. Klonlama ve Derleme
```bash
git clone https://github.com/1Ssalih/SpecterRecon.git
cd SpecterRecon
go mod download

# Yerel mimari için derleme (Apple Silicon arm64 veya Intel amd64)
go build -trimpath -ldflags="-s -w" -o specter-recon main.go

# PATH dizinine kopyalama
sudo cp specter-recon /usr/local/bin/
```

> **macOS Notu:** Masscan kullanımı macOS üzerinde `sudo` gerektirebilir:
> `sudo specter-recon scan 192.168.1.0/24 --use-masscan --authorized`

---

### 🪟 Windows (Windows 10, 11 & Windows Server)

#### Yöntem A: PowerShell ile Kaynak Koddan Derleme
1. [Go Resmi Sitesi](https://go.dev/dl/)'nden Go (1.26+) kurulumunu yapın.
2. [Npcap](https://npcap.com/)'i (WinPcap uyumluluk modu seçili olarak) kurun (Masscan/Nmap kullanımı için gereklidir).
3. PowerShell'i açın ve çalıştırın:
```powershell
# Repoyu klonlayın
git clone https://github.com/1Ssalih/SpecterRecon.git
cd SpecterRecon

# Bağımlılıkları indirin
go mod download

# Windows için .exe derleyin
go build -trimpath -ldflags="-s -w" -o specter-recon.exe main.go

# Test edin
.\specter-recon.exe --help
```

#### Yöntem B: Linux / macOS Üzerinden Windows İçin Çapraz Derleme (Cross-Compilation)
```bash
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o specter-recon.exe main.go
```

---

### 🐳 Docker / Container ile Çalıştırma

SpecterRecon'u izole bir konteynerde çalıştırmak için:

```dockerfile
# Multi-stage build Dockerfile
FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY . .
RUN apk add --no-cache git libpcap-dev gcc musl-dev
RUN go mod download
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o specter-recon main.go

FROM alpine:latest
RUN apk add --no-cache libpcap nmap masscan ca-certificates
COPY --from=builder /app/specter-recon /usr/local/bin/specter-recon
COPY --from=builder /app/config.yaml /app/config.yaml
WORKDIR /app
ENTRYPOINT ["specter-recon"]
```

**Docker ile Çalıştırma:**
```bash
# İmajı oluşturun
docker build -t specter-recon .

# Host network yetkisi ile tarama yapın
docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN -v $(pwd)/output:/app/output specter-recon scan example.com --authorized
```

---

## 🚀 12. Kapsamlı Komut Satırı Kullanım Kılavuzu (CLI Reference & Examples)

### 1. İnteraktif Konsol Modu (Parametresiz Çalıştırma)
```bash
specter-recon
```

### 2. Uçtan Uca Boru Hattı Taraması (`scan` & `fullscan`)

```bash
# 🎯 Standart Boru Hattı Taraması (DNS + Host + Port + Banner + Catch-All Web Fuzzing)
specter-recon scan example.com --authorized

# 🛡️ Genişletilmiş Tam Denetim (Subdomain Brute-force + SSL/TLS + HTTP Headers + CORS + SSH Audit)
specter-recon fullscan example.com --subdomains --authorized

# ⚡ Saldırgan Tarama Profili (Masscan + Nmap NSE + SecLists Raft Wordlist)
specter-recon scan 10.0.0.0/16 --profile aggressive --authorized

# 🤫 Sessiz / Stealth Tarama Profili (20 Worker, 100ms adaptif gecikme)
specter-recon scan target.local --profile stealth -d 100 --authorized

# 🔢 Tüm 65535 Portu 200 Eşzamanlı Worker İle Tara
specter-recon scan 10.0.0.100 -p 1-65535 -t 200 --authorized

# 📥 Önceden Alınmış Nmap XML Çıktısını İçe Aktarma (-oX)
specter-recon scan --nmap-xml nmap_results.xml --authorized

# 📥 Önceden Alınmış Masscan JSON Çıktısını İçe Aktarma ve TCP Handshake ile Doğrulama (-oJ)
specter-recon scan --masscan-json masscan_out.json --authorized
```

### 3. Bağımsız Alt Modül Komutları

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

# 🔒 SSL/TLS Sertifika, Zayıf Cipher & Güvenlik Başlıkları Audit
specter-recon ssl example.com:443 --authorized

# 📊 Mevcut Çıktılardan HTML Dashboard Raporu Üretme
specter-recon report -t "Kurumsal Güvenlik Denetim Raporu" --authorized
```

---

## ⚙️ 13. Yapılandırma Dosyası (`config.yaml`)

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

Tarama tamamlandığında `output/` klasöründe aşağıdaki dosyalar oluşturulur:

1. **`output/report.html` (Görsel SOC Dashboard):** Glassmorphism CSS teması, WAF rozetleri, Nmap NSE Zafiyet Bulguları kartı, Secret Sızıntıları tablosu ve Masscan Çelişkili Portlar tablosu içeren interaktif HTML raporu.
2. **`output/summary.txt` (Konsolide Metin Özeti):** Tüm host, port, servis, tam versiyon, güven skoru ve zafiyet özetini içeren yönetici özeti.
3. **`output/services.json`:** Her servis için kanıt dizisi (`evidence`), güven skoru (`confidence`), WAF bilgisi ve TLS sertifika detaylarını içeren yapılandırılmış JSON verisi.
4. **`output/findings.txt`:** Catch-All sahte bulgularından arındırılmış, durum kodları ve hassas dosya etiketleri içeren web bulguları.
5. **`output/ip_list.json`:** DNS, SRV ve Ters DNS sorgularından elde edilen tüm doğrulanmış IP listesi.
6. **`audit.log`:** SOC ve yasal uyumluluk için zaman damgalı tüm tarama ve komut denetim izi.

---

## 📋 15. Günlük Tutma, Denetim İzi (Audit Log) & Uyumluluk

SpecterRecon, kurumsal sızma testleri ve ISO 27001 / SOC 2 uyumluluk süreçleri için tüm eylemleri `audit.log` dosyasına otomatik olarak yazar:

```text
2026-08-31 10:24:13 [AUDIT] ACTION=DIR_FUZZ_START TARGET="http://10.0.0.100" DETAILS="words=2500, matchTag=iis, concurrency=25" STATUS=SUCCESS
2026-08-31 10:24:14 [AUDIT] ACTION=SECRET_LEAK_DETECTED TARGET="http://10.0.0.100/config.json" DETAILS="leaks=[AWS Access Key, JWT Token]" STATUS=ALERT
```

---

## ⚖️ 16. Yasal Uyarı ve Lisans

> ⚠️ **YASAL UYARI:**  
> **SpecterRecon**, yalnızca **yasal olarak izin alınmış güvenlik denetimleri**, sızma testleri, kurum içi altyapı kontrolleri ve eğitim lab ortamları için geliştirilmiştir. Yetkisiz sistemlere karşı izin almadan tarama yapmak yasalara (TCK Madde 243/244, 5651 Sayılı Kanun, US CFAA vb.) aykırıdır ve ağır cezai sorumluluk doğurur.  
> Geliştirici, aracın kötüye kullanımından doğabilecek hiçbir zarardan sorumlu tutulamaz.

### Lisans
Bu proje **[MIT Lisansı](LICENSE)** altında lisanslanmıştır.

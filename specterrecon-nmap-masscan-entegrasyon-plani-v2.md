# SpecterRecon — Nmap & Masscan Entegrasyonu Mimari Planı (v2)

**Hedef Platform:** Ubuntu / Kali Linux (Windows desteği kapsam dışı)
**Amaç:** Native Go motorunun taşınabilirliğini korurken, isteğe bağlı olarak Nmap/Masscan gücünü sisteme kazandırmak.

---

## 1. Tasarım Felsefesi

| İlke | Açıklama |
|---|---|
| **Opsiyonel, asla zorunlu değil** | `nmap`/`masscan` sistemde yoksa araç %100 native Go motoruyla çalışmaya devam eder. |
| **Kaynak şeffaflığı** | Her veri noktasının hangi araçtan geldiği (`native` / `masscan` / `nmap`) raporda görünür olur. |
| **Hız/gizlilik ayrımı profille yönetilir** | Kullanıcı tek bir global davranış yerine, o taramaya özel bir profil seçer. |
| **Doğrulama katmanı** | Masscan gibi stateless araçların "açık" dediği portlar, mümkün olduğunca native handshake ile teyit edilir (false-positive azaltma). |

---

## 2. Tarama Profilleri

```
--profile aggressive   → Masscan (raw SYN) + Nmap NSE, gecikme yok, tüm portlar
--profile balanced     → Native Go worker pool (varsayılan davranış, mevcut sistem)
--profile stealth      → Native Go, sınırlı worker sayısı, port sırası randomize, -d gecikmeli
```

**Kural:** Masscan sadece `aggressive` profilinde devreye girer. `stealth` profilinde Masscan/Nmap NSE'ye hiç dokunulmaz.

---

## 3. Aşamalı Uygulama Planı

### Seviye 1 — İçe Aktarma (Import) Modu ✅ *Öncelik*
```bash
specter-recon scan --nmap-xml nmap_results.xml --authorized
specter-recon banner -i masscan_output.json --authorized
```
Dış süreç tetiklemesi yok, sadece parser. Risk: düşük.

### Seviye 2 — Subprocess Wrapper
```bash
specter-recon scan 10.0.0.0/16 --use-masscan --profile aggressive --authorized
specter-recon scan example.com --use-nmap-nse --authorized
```
- `exec.LookPath` ile önkontrol, yoksa native motora graceful fallback
- `context.WithTimeout` zorunlu
- stdout/stderr ayrı goroutine'lerde okunur (deadlock önleme)

### Seviye 3 — NSE Sonuçlarının Otomatik Entegrasyonu
Açık bulunan servise özel NSE script tetikleme (bkz. Bölüm 6 — karar netleşti).

**Not:** Seviye 1 tam stabilize olmadan Seviye 2'ye geçilmeyecek.

---

## 4. Veri Modeli Değişiklikleri (`core/models.go`)

```go
type Port struct {
    // ...mevcut alanlar...
    Source     string `json:"source"`      // "native" | "masscan" | "nmap"
    Verified   bool   `json:"verified"`     // native handshake ile teyit edildi mi?
    Conflict   bool   `json:"conflict"`     // kaynaklar arası çelişki var mı? (bkz. Bölüm 7)
}
```

---

## 5. Root / Yetki Yönetimi

```bash
sudo setcap cap_net_raw,cap_net_admin=eip specter-recon
```
`--profile aggressive` seçilip capability eksikse, sessizce native moda düşmek yerine kullanıcıyı `setcap` komutuna yönlendiren açık hata verilir.

---

## 6. Karar: NSE Script Eşlemesi — `config.yaml` Üzerinden Özelleştirilebilir

**Karar:** Sabit (hardcoded) liste yerine, **`config.yaml` içinde sensible default'larla gelen, kullanıcı tarafından override edilebilir bir eşleme** kullanılacak.

**Neden bu karar mantıklı:**
- Proje zaten `config.yaml` ile merkezi yapılandırma kültürüne sahip (README'de belirtilmiş) — tutarlılık için aynı deseni izlemek doğru.
- Sabit liste kodda gömülü olursa, yeni bir NSE script eklemek her seferinde derleme (rebuild) gerektirir. Config'te tutmak, kullanıcının kendi ortamına özel script eklemesine (örn. özel bir CVE için yazdığı script) izin verir.
- Varsayılanlar yine de "battery-included" olmalı — kullanıcı hiç dokunmazsa mantıklı bir set otomatik çalışmalı.

```yaml
nse_mappings:
  445:
    - smb-vuln-ms17-010
  443:
    - ssl-heartbleed
    - ssl-cert
  http:  # port numarası yerine servis adıyla da eşleşebilir
    - http-vuln-cve2021-41773
```

---

## 7. Karar: Kaynak Çelişkisi — Ayrı "Conflict" Bölümü

**Karar:** Masscan "açık", native handshake "kapalı/erişilemez" derse, bu port **sessizce elenmez veya rastgele bir tarafa yazılmaz** — `Conflict: true` olarak işaretlenir ve HTML raporunda ayrı, görsel olarak vurgulanmış bir "⚠️ Çelişkili Bulgular" bölümünde listelenir.

**Neden bu karar mantıklı:**
- Projenin zaten benimsediği "kaynak şeffaflığı" ilkesiyle birebir tutarlı (Bölüm 1).
- Bir pentester için "bu port belki açık, belki SYN-proxy arkasında" bilgisi kritik — sessizce gizlenirse güven kaybı, yanlışlıkla "kapalı" yazılırsa gerçek bir açığı kaçırma riski oluşur. En güvenli seçim: göstermek ama etiketlemek.
- Ekstra maliyeti düşük — zaten `Verified` alanı hesaplanıyor, `Conflict = (Source == "masscan" && !Verified)` mantığıyla türetilebilir.

---

## 8. Karar: Audit Log Boyut Yönetimi — Özet Satır + Ayrı Detay Dosyası

**Karar:** `audit.log` **her port için değil, host/işlem bazında özet satırlar** tutar. Port-seviyesi ham detaylar zaten `output/ports.json` içinde var — audit.log'un amacı "ne zaman, kim, hangi yetkiyle, ne yaptı" sorularını cevaplamak, ham veri deposu olmak değil.

```
[TIMESTAMP] tool=masscan profile=aggressive target=10.0.0.0/16 hosts_scanned=65536 open_ports_found=142 duration=12.4s
[TIMESTAMP] tool=nmap-nse target=192.168.1.10 scripts_run=3 vulnerabilities_found=1 duration=4.2s
```

**Neden bu karar mantıklı:**
- /16 gibi büyük ağlarda port-bazlı loglama, dosyayı dakikalar içinde yüzlerce MB'a çıkarabilir — hem disk hem de log'u insan gözüyle okuma amacını (denetim/audit) baltalar.
- Detaylı veri zaten JSON çıktılarında var; audit.log'u tekrar aynı veriyi taşımak yerine "meta-kayıt" olarak tutmak, hem performans hem okunabilirlik açısından daha doğru.
- İleride log rotasyonu (`audit.log` belli boyutu geçince `audit.log.1` şeklinde arşivlenmesi) eklenmesi de bu sayede kolaylaşır — özet satırlar küçük olduğu için rotasyon nadiren gerekir.

---

## 9. Fuzzer Güçlendirmeleri (Nmap/Masscan'den Bağımsız)

| Geliştirme | Amaç |
|---|---|
| **Soft-404 / catch-all tespiti** | Response-size ve status code kombinasyonuna bakarak WAF'ın "her yola 200 dönme" tuzağını tespit eder. |
| **Adaptif rate-limiting** | 429 alındığında worker sayısı otomatik düşürülür. |
| **Genişletilmiş `service_wordlist_map.yaml`** | Tespit edilen teknolojiye göre daha isabetli wordlist havuzları. |

---

## 10. Riskler ve Azaltım Özeti

| Risk | Azaltım |
|---|---|
| Nmap/Masscan sürüm farklılıklarında parse hatası | Toleranslı parser, birden fazla sürüm örneğiyle unit test |
| Masscan false-positive (SYN-proxy) | Native handshake doğrulaması + Conflict etiketleme (Bölüm 7) |
| IDS/IPS tetiklenmesi | Profil ayrımı, varsayılan `balanced` |
| Process donması | `context.WithTimeout` zorunlu |
| Root/capability eksikliği | Açık hata mesajı + `setcap` yönlendirmesi |
| NSE listesi güncel kalmıyor | `config.yaml` üzerinden kullanıcı override (Bölüm 6) |
| Audit log şişmesi | Özet satır + JSON'a referans (Bölüm 8) |

---

## 11. Önerilen Uygulama Sırası

1. **Veri modeli güncellemesi** — `Source`/`Verified`/`Conflict` alanları
2. **`config.yaml` şema genişletmesi** — `nse_mappings` bölümü + varsayılanlar
3. **Seviye 1: Nmap XML import parser** — `modules/nmapimport.go`
4. **Seviye 1: Masscan JSON import parser** — `modules/masscanimport.go`
5. **Profil sistemi** — `cmd/scan.go` içine `--profile` bayrağı
6. **Seviye 2: Subprocess wrapper** — `exec.LookPath` + timeout + fallback
7. **Doğrulama + Conflict katmanı** — native handshake teyidi
8. **Audit log özet formatı** — `core/logger.go` güncellemesi
9. **Fuzzer geliştirmeleri** — soft-404, adaptif rate-limit
10. **Seviye 3: NSE otomatik entegrasyonu** — en son, en yüksek risk

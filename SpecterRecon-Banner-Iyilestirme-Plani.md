# SpecterRecon — Banner Grabbing & Versiyon Tespiti İyileştirme Planı

> Kapsam: Sadece keşif/parmak izi doğruluğu. CVE/exploit tarafı bilinçli olarak dışarıda tutuldu.
> Kaynak: `fullscan milsoft.com.tr` test çıktısı analizi (41 açık port, 3 gerçek versiyon tespiti)

---

## 1. Test Sonucundan Çıkan Teşhis

`services.json` çıktısında 41 servisten sadece **3 tanesinde** gerçek versiyon bilgisi var (VNC, FSSO, ve yanlış etiketlenmiş SIP/HTTP). Geri kalan 38 servis (Kerberos, MSRPC, NetBIOS, LDAP, LDAPS, microsoft-ds/SMB, RDP, DNS) için "Versiyon/Başlık" alanı boş (`-`) ve "Açıklama" alanı sadece port numarasından statik isim ataması (`"LDAP Service"`, `"KERBEROS Service"` vb.).

**Kök sebep:** Mevcut mantık yalnızca *kendiliğinden veri gönderen* servislerde (VNC, HTTP) çalışıyor. TCP bağlanıp sunucunun konuşmasını bekleyen, ama önce bir tetikleyici (probe) isteyen servislerde tamamen boş dönüyor.

---

## 2. Acil Düzeltilmesi Gereken Bug

### 🐞 SIP yanlış tespiti
- `10.0.0.100:80`, `:5985` gibi portlar **SIP** olarak etiketlenmiş.
- Banner içeriği açıkça `HTTP/1.1 400 Bad Request` + `Server: Microsoft-HTTPAPI/2.0` — bu **HTTP**, SIP değil.
- Muhtemel sebep: servis sınıflandırma regex/switch mantığında "HTTPAPI" string'i yanlış bir kurala çarpıyor.
- **Aksiyon:** `modules/banner.go` içindeki servis sınıflandırma tablosunu gözden geçir, HTTP response imzasını (`HTTP/1.x` ile başlama) SIP'ten önce kontrol et.
- **Efor:** Düşük — **Öncelik:** Yüksek (kolay çözülür, doğruluğu doğrudan bozuyor)

---

## 3. Yüksek Etkili Yeni Özellikler (Öncelik Sırasına Göre)

### 🥇 3.1 SMB NTLMSSP ile OS Fingerprinting
- **Neden en yüksek öncelik:** Test edilen 4 host da Windows/AD ortamı (LDAP+Kerberos+SMB birlikte açık → muhtemelen Domain Controller). Şu an `445/microsoft-ds` için sıfır bilgi var.
- **Nasıl:** SMB2 NEGOTIATE isteği gönder → cevaptaki NTLMSSP NEGOTIATE mesajını parse et → `NTLM Version` alanından tam OS build numarası çıkar (örn. "Windows Server 2019 Build 17763"). Kimlik doğrulama gerekmez, sadece negotiate/session-setup handshake.
- **Referans yaklaşım:** `nmap --script smb-os-discovery`, CrackMapExec aynı tekniği kullanır.
- **Go tarafı:** `github.com/hirochachacha/go-smb2` gibi bir kütüphane veya ham SMB2 paket inşası.
- **Etki:** Şu an tamamen boş olan 4 host için gerçek OS/versiyon bilgisi.
- **Efor:** Orta-Yüksek — **Öncelik:** 1

### 🥈 3.2 LDAP Anonim RootDSE Sorgusu
- **Neden:** `389`/`636` portları için sıfır bilgi var. Anonim bind + boş base scope arama (rootDSE) genelde izin gerektirmez.
- **Dönebilecek alanlar:** `supportedLDAPVersion`, `defaultNamingContext`, `rootDomainNamingContext`, `domainControllerFunctionality` (bu değer doğrudan Windows Server versiyonuna karşılık gelir: 7=2016+, 6=2012R2, vb.)
- **Etki:** 4 domain controller'da da çalışması muhtemel, ek kimlik doğrulama gerektirmez (pure recon kapsamında kalır).
- **Efor:** Orta — **Öncelik:** 2

### 🥉 3.3 Aktif Probe Zinciri (Genel Altyapı)
- **Neden:** Sadece SMB/LDAP değil, tüm "sessiz" portlar için genel çözüm.
- **Nasıl:** Bağlan → kısa süre bekle (1 sn) → veri gelmediyse portun bilinen protokolüne özel bir tetikleyici gönder → tekrar oku (2-3 sn deadline ile).
  ```go
  conn.SetReadDeadline(time.Now().Add(1 * time.Second))
  n, err := conn.Read(buf)
  if n == 0 {
      conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n")) // protokole göre değişir
      conn.SetReadDeadline(time.Now().Add(2 * time.Second))
      n, err = conn.Read(buf)
  }
  ```
- **Etki:** Nmap'in `service_probes` mantığına benzer, sessiz portlarda tespit oranını genel olarak artırır.
- **Efor:** Orta — **Öncelik:** 3

### 3.4 TLS SNI Düzeltmesi (443 Bağlantı Hatası)
- **Test çıktısındaki hata:** `10.0.0.100:443: TLS bağlantısı kurulamadı ... wsarecv: An existing connection was forcibly closed`
- **Muhtemel sebep:** `tls.Config` içinde `ServerName` (SNI) set edilmemiş; IIS gibi sunucular SNI olmadan bağlantıyı sert kapatabilir.
- **Çözüm:**
  ```go
  tls.Config{
      ServerName: host,
      InsecureSkipVerify: true,
      MinVersion: tls.VersionTLS10,
  }
  ```
- **Efor:** Düşük — **Öncelik:** 4

### 3.5 RDP Sertifika/Hostname Çekimi
- **Neden:** SSL modülü 636 portlarından hostname çekmeyi zaten başarıyor (`2012dc1`, `DC1`, `MilsoftDCFKM`, `MILDC3`). Aynı mantık RDP'nin TLS/NLA katmanına da uygulanabilir.
- **Nasıl:** 3389 üzerinde X.224 handshake sonrası TLS varsa sertifika CN'i çek.
- **Etki:** RDP satırlarına ek bağlam bilgisi ("Microsoft RDP" yerine hostname/sertifika detayı).
- **Efor:** Orta — **Öncelik:** 5

---

## 4. Genel Doğruluk İyileştirmeleri (Orta Vadeli)

### 4.1 Favicon Hash (mmh3) ile Banner'sız Tespit
- Shodan'ın kullandığı teknik. Favicon murmur3 hash'i birçok ürüne (Jenkins, Grafana, phpMyAdmin vb.) özgüdür, HTTP banner'ı silinmiş olsa bile ürün tespiti sağlar.

### 4.2 Güven Skoru (Confidence) Modeli
- `Service` struct'ına `Confidence float64` ve `Signals []string` alanları ekle.
- Örnek: banner'dan doğrudan versiyon geldiyse "yüksek güven"; sadece port numarasından tahmin edildiyse "düşük güven, tahmini" olarak raporda ayrı göster.
- Rakip araçların çoğu (Nmap dahil) bunu şeffaf göstermiyor — ayırt edici bir özellik olabilir.

### 4.3 Regex Kütüphanesini Dışsallaştır
- Şu an muhtemelen kod içine gömülü olan servis imzası regex'lerini `wordlists/` klasöründeki mantığa benzer şekilde ayrı bir `fingerprints.yaml` dosyasına taşı.
- Yeni imza eklemek kod değiştirmeden mümkün olsun (case-insensitive regex, çoklu varyant desteği).

### 4.4 Buffer / Okuma Stratejisi
- Küçük buffer (`1024` byte) yerine en az `4096` byte kullan.
- `io.ReadFull` yerine `bufio.Reader` ile satır satır okuma, header setlerinin kırpılmasını önler.

### 4.5 Banner Grab için Ayrı Worker Pool
- Port tarama hızlı goroutine pool'u ile aynı agresif paralellik/timeout ayarını banner grab adımına uygulamak veri kaybına yol açabilir.
- Banner grab için daha az goroutine + daha uzun timeout'lu ayrı bir worker pool kullan.

---

## 5. Önerilen Uygulama Sırası (Özet)

| # | Görev | Etki | Efor |
|---|-------|------|------|
| 1 | SIP/HTTP yanlış etiketleme bug fix | Yüksek | Düşük |
| 2 | SMB NTLMSSP OS fingerprinting | Çok Yüksek | Orta-Yüksek |
| 3 | LDAP anonim rootDSE sorgusu | Yüksek | Orta |
| 4 | TLS SNI düzeltmesi (443 hatası) | Orta | Düşük |
| 5 | Genel aktif probe zinciri | Yüksek (genel) | Orta |
| 6 | RDP sertifika/hostname çekimi | Orta | Orta |
| 7 | Favicon hash tespiti | Orta | Orta |
| 8 | Confidence skoru modeli | Orta (ayırt edicilik) | Orta |
| 9 | Regex/fingerprint dışsallaştırma | Uzun vadeli bakım | Orta |
| 10 | Buffer/worker pool ayarları | Genel iyileştirme | Düşük |

---

## 6. Kapsam Dışı (Bilinçli Olarak Yapılmıyor)

- CVE/NVD eşleştirmesi, exploit önerisi, saldırı vektörü üretimi — proje amacı tespit/keşif, saldırı değil.

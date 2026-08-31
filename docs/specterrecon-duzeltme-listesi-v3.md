# SpecterRecon — Kapsamlı Düzeltme Listesi (v3)

**Son güncelleme:** 31 Ağustos 2026
**Kaynaklar:** GitHub repo incelemesi (`v1.1.0`, taze) + gerçek `fullscan` tarama logu analizi
**Kapsam:** Repo hijyeni + runtime/mantık hataları + Nmap/Masscan yol haritası (özet)

---

## 🔴 BÖLÜM A — Gerçek Tarama Logunda Tespit Edilen Fonksiyonel Hatalar

Bunlar teorik değil; gerçek bir `fullscan` çalıştırmasının çıktısında doğrudan gözlemlendi.

### A1. 🔴 EN KRİTİK — Catch-All (Wildcard) Tespiti Status Code'a Göre Tutarsız Çalışıyor
- **Kanıt:** `10.0.0.88:443` hedefinde 203 kelimenin neredeyse tamamı `302 Object moved`, 128–140B boyutunda döndü — klasik "her yola aynı redirect" (login sayfasına yönlendirme) davranışı. Ancak log'da bu hedef için **hiçbir** "Catch-All Tespit Edildi" uyarısı basılmadı. Aynı domain'in 80 ve 81 portlarında ise (403 status'lü catch-all) doğru şekilde tespit edilip filtrelendi:
  ```
  [16:18:24] [!] WARNING Catch-All / Wildcard Yanıtı Tespit Edildi: ...403 (~0B)...
  [16:18:27] [!] WARNING Catch-All / Wildcard Yanıtı Tespit Edildi: ...403 (~1233B)...
  ```
  Aynı problem `10.0.8.185:80` için de var — 60+ path tamamen aynı `401`/`16B` imzasıyla döndü, yine hiç tespit edilmedi.
- **Sonuç:** Rapor `aspxshell.aspx`, `zehir.aspx`, `web.config`, `wp-config.php` gibi **60+ path'i "[KRİTİK DOSYA]"** olarak işaretledi — hepsi sahte pozitif, gerçek dosya değil.
- **Kök neden (tahmin):** Catch-all algoritması yalnızca `403` status code'una göre tetikleniyor gibi görünüyor; `302` ve `401` durumları kapsanmıyor.
- **Yapılacak:**
  - [ ] `modules/dirfuzz.go` içindeki catch-all tespit fonksiyonunu bul
  - [ ] Tespiti status code'dan bağımsız hale getir: "N path'e giden isteklerin çoğu aynı (status, boyut±tolerans) imzasını taşıyorsa wildcard'dır" mantığı
  - [ ] Response body'sinin bir kısmını (örn. ilk 100 byte hash'i) de imzaya dahil etmeyi değerlendir — sadece boyut bazlı kıyas bazen yanıltıcı olabilir
  - [ ] Birim testi ekle: 302/401/403/200 durumlarının her biri için ayrı catch-all senaryosu simüle eden test

### A2. 🟡 Host Discovery ile Port Scan Sonuçları Çelişiyor
- **Kanıt:**
  ```
  Host Discovery: 10.0.1.110 ➔ ALIVE (tcp_ping:80, 8.85ms)
  Port Taraması:  10.0.1.110 ➔ 0 açık port (2 kez denendi, thread azaltılarak)
  ```
  Host, port 80 üzerinden TCP bağlantısıyla canlı bulundu — yani port 80 açık olmalı. Ama port tarayıcı aynı porta baktığında iki denemede de "0 açık port" buldu.
- **Yapılacak:**
  - [ ] `modules/discovery.go` ve `modules/portscan.go` içindeki TCP connect mantığını (timeout süresi, dial yöntemi) karşılaştır
  - [ ] İki modülün aynı bağlantı stratejisini kullandığından emin ol; farklıysa birleştir (tek bir ortak `tcpProbe()` yardımcı fonksiyonu düşünülebilir)
  - [ ] Otomatik retry mantığının (thread sayısını düşürerek tekrar deneme) gerçekten sorunu çözüp çözmediğini doğrula — şu anki haliyle işe yaramıyor

### A3. 🟡 Log Formatlama Hatası — Boş Parantezler
- **Kanıt:** `Host Discovery tamamlandı: 1 canlı host kaydedildi ().` — her satırın sonunda boş `()`.
- **Yapılacak:**
  - [ ] `core/logger.go` içinde ilgili `Sprintf`/format string'i bul, unutulmuş değişkeni (muhtemelen dosya yolu) doldur ya da parantezi kaldır

### A4. 🟡 Performans Anomalisi — Her Yeni Host'ta ~1 Saniyelik Sabit Gecikme
- **Kanıt:** Her yeni hedef IP'nin ilk birkaç portu tutarlı şekilde ~1000–1200ms (bazen 2242ms) gecikmeyle geliyor, aynı host'un sonraki portları 4–15ms gibi normal hızlara dönüyor. Bu örüntü 7 host boyunca tekrarlanıyor.
- **Yapılacak:**
  - [ ] `modules/portscan.go` içinde her yeni host için yapılan ilk bağlantıda blocking bir reverse-DNS (PTR) lookup çağrısı olup olmadığını kontrol et
  - [ ] Worker pool'un host başına "ısınma" (goroutine spin-up senkronizasyonu) gecikmesi yaşayıp yaşamadığını profilleme (`pprof`) ile doğrula
  - [ ] Bulgu doğrulanırsa: reverse-DNS lookup'ı ayrı bir goroutine'e taşı / timeout ekle / sonuçları bloklamadan cache'le

### A5. 🟢 Boş Modül Başlığı — SSH Denetimi
- **Kanıt:** `GENIŞLETILMIŞ MODÜL: SSH ALGORITMA & KONFİGÜRASYON DENETİMİ` başlığı basılıyor ama hedefte SSH portu olmadığı için altında hiç satır yok — kullanıcı bunun hata mı beklenen davranış mı olduğunu ayırt edemiyor.
- **Yapılacak:**
  - [ ] SSH servisi bulunamadığında `[*] INFO 0 SSH servisi bulundu, modül atlandı` gibi açık bir satır ekle

### A6. 🟢 SSL/TLS Bağlantı Hatası — İncelenmeli
- **Kanıt:** `10.0.0.100:443` için `TLS bağlantısı kurulamadı: read: connection reset by peer` hatası alındı, ama aynı host'ta banner grab modülü portu `https` olarak başarıyla tanımlamıştı.
- **Yapılacak:**
  - [ ] SNI (Server Name Indication) gönderilip gönderilmediğini kontrol et — bazı sunucular SNI olmadan bağlantıyı reddeder
  - [ ] `InsecureSkipVerify` ve TLS handshake timeout ayarlarını gözden geçir

---

## 🟠 BÖLÜM B — Repo Hijyeni (Bir Kısmı Zaten Düzeltilmiş)

### B1. ✅ Düzeltildi — `.gitignore` / `output/` Güvenliği
- `output/`, `*.log`, `audit.log`, derlenmiş binary'ler ve `.env`/`secrets.yaml` gibi dosyalar artık `.gitignore` içinde kapsanıyor (taze kontrol edildi, doğrulandı).

### B2. ⚠️ Hâlâ Kontrol Edilmeli — Go Sürüm Tutarlılığı
- README badge `Go 1.26+` gösteriyor. `go.mod` içeriği önbellek sorunları nedeniyle net doğrulanamadı.
- **Yapılacak:**
  - [ ] `go.mod` içindeki `go` direktifinin gerçekten `1.26` (veya üstü) olduğunu teyit et
  - [ ] CI'da (bkz. B4) gerçek derleme ortamının bu sürümle eşleştiğinden emin ol

### B3. 🟡 LICENSE Dosyası Hâlâ Yok
- **Yapılacak:**
  - [ ] MIT veya Apache 2.0 lisansı seç, `LICENSE` dosyasını repo köküne ekle

### B4. 🟡 CI/CD Hâlâ Yok
- **Yapılacak:**
  - [ ] `.github/workflows/ci.yml` ekle: her push/PR'da `go build ./...`, `go vet ./...`, `go test -v ./...` çalıştır
  - [ ] Bu, A1–A6'daki gibi bug'ların merge öncesi otomatik yakalanmasını sağlar (özellikle `modules_test.go` içine A1 ve A2 için yeni testler eklendiğinde)

### B5. 🟢 Dağınık Plan Dosyaları
- `proje-plani.md`, `proje-plani (1).md`, `python-to-go-rehberi.md` hâlâ repo kökünde, son kullanıcı için gürültü oluşturuyor.
- **Yapılacak:**
  - [ ] Duplike `proje-plani (1).md` dosyasını sil (hangisi güncelse onu tut)
  - [ ] Kalan geliştirme notlarını `docs/` klasörüne taşı ya da repodan çıkar

---

## 🟢 BÖLÜM C — Nmap/Masscan Entegrasyonu (Önceki Plandan Özet)

Detaylı gerekçeler önceki mimari plan dokümanında mevcut; burada sadece uygulama sırası özetlenmiştir.

- [ ] **C1.** Veri modeli: `core/models.go` içine `Source`, `Verified`, `Conflict` alanları
- [ ] **C2.** `config.yaml` içine `nse_mappings` bölümü (varsayılanlarla, override edilebilir)
- [ ] **C3.** Seviye 1 — Nmap XML import parser (`modules/nmapimport.go`)
- [ ] **C4.** Seviye 1 — Masscan JSON import parser (`modules/masscanimport.go`)
- [ ] **C5.** Profil sistemi — `cmd/scan.go` içine `--profile aggressive|balanced|stealth`
- [ ] **C6.** Seviye 2 — Subprocess wrapper (`exec.LookPath` + `context.WithTimeout` + fallback)
- [ ] **C7.** Doğrulama + Conflict katmanı (native handshake teyidi)
- [ ] **C8.** Audit log özet formatı (host/işlem bazlı, port bazlı değil)
- [ ] **C9.** Root/capability yönetimi (`setcap` yönlendirmesi)
- [ ] **C10.** Fuzzer geliştirmeleri — **not: A1'deki catch-all düzeltmesi bu adımdan önce yapılmalı**, çünkü aynı kod yolunu paylaşıyorlar
- [ ] **C11.** Seviye 3 — NSE otomatik entegrasyonu

---

## 📌 Önerilen Genel Öncelik Sırası

1. **A1 (catch-all bug)** — en yüksek öncelik; hâlihazırda üretimde yanlış "kritik bulgu" raporluyor, aracın güvenilirliğini doğrudan etkiliyor
2. **A2 (host discovery/port scan çelişkisi)** — gerçek açık portları kaçırma riski taşıyor (false negative), A1'den de tehlikeli olabilir çünkü sessizce veri kaybettiriyor
3. **B3 + B4 (LICENSE + CI/CD)** — CI/CD kurulduktan sonra A1/A2 için regresyon testleri otomatik korunur
4. **A4 (performans anomalisi)** — büyük taramalarda toplam süreyi ciddi etkiliyor, kullanıcı deneyimini bozuyor
5. **A3, A5, A6, B2, B5** — düşük risk, hızlıca temizlenebilir
6. **Bölüm C (Nmap/Masscan)** — temel repo sağlığı ve mevcut fuzzer/scanner hataları giderildikten sonra

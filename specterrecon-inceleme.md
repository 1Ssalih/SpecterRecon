# SpecterRecon — Kod İnceleme Raporu & Düzeltme Planı

> İnceleme yöntemi: repo `git clone` ile indirildi, tüm `.go` dosyaları okundu, `gofmt` ile sözdizimi kontrolü yapıldı. Sandbox'ın ağ izin listesi `proxy.golang.org`, `atomicgo.dev`, `golang.org`, `gopkg.in` gibi bağımlı paket kaynaklarına izin vermediği için **tam `go build` yapılamadı** — bu yüzden derleme hatası garantisi veremiyorum, ama kod okuması ile bulunan sorunlar aşağıda kanıtlarıyla birlikte listeleniyor. Kendi makinende `go build ./...` çalıştırıp çıkan hataları paylaşırsan onları da ekleriz.

---

## 🔴 KRİTİK — Güvenlik Guardrail'i Devre Dışı Kalıyor

**Dosya:** `cmd/shell.go`, satır ~26

```go
// In interactive shell mode, user is authorized
authorizedFlag = true
```

**Sorun:** `--authorized` flag'i ve `verifyScopePermission()` fonksiyonu, kullanıcının hedefi taramaya yasal izni olduğunu onaylatmak için tasarlanmıştı (bizim planımızdaki "Güvenlik & Etik Guardrail" maddesi). Ama **interaktif shell moduna girildiği anda** (`cmd/root.go`'da `RootCmd.Run` argümansız çalıştırıldığında shell'e düşüyor — yani programı hiç argümansız çalıştırmak bile bu moda giriyor) `authorizedFlag` global olarak `true`'ya sabitleniyor. Sonuç: shell modunda hangi hedefe karşı `scan`/`fullscan`/`smb`/`creds` gibi herhangi bir komut çalıştırılırsa çalıştırılsın, **izin onayı hiç sorulmuyor**.

Bu, tasarladığımız guardrail'in amacını doğrudan boşa çıkarıyor — üstelik shell, programın **varsayılan davranışı** (argümansız çalıştırınca oraya düşüyor).

**Nasıl düzeltilir:**
- `authorizedFlag = true` satırını tamamen kaldır.
- Onayı global bir flag yerine, shell içinde **her komut çalıştırılmadan hemen önce** o an girilen hedefe özel sorulacak şekilde değiştir (yani `verifyScopePermission(target)` çağrısı shell'in komut çalıştırma döngüsünün içine, her satır işlenmeden önce eklenmeli).
- Alternatif (daha basit): shell moduna girişte tek seferlik genel bir onay sorulsun ("Bu oturumdaki tüm taramalar için yasal izniniz var mı?"), ama bunun her komut için ayrı ayrı sorulan onaydan daha zayıf bir güvence olduğunu bil.

---

## 🔴 SecList Entegrasyonu Aslında Hiç Yok

Senin şüphelendiğin nokta doğruydu. Kontrol ettim:

```bash
$ grep -ril "seclist" .
(sonuç: boş — kod içinde "seclist" kelimesi bir kez bile geçmiyor)

$ cat .gitmodules
(dosya yok — git submodule tanımlı değil)
```

**Gerçek durum:** `wordlists/` klasöründeki dosyalar gerçek SecLists reposundan değil, elle yazılmış küçük listeler:

| Dosya | Satır sayısı | Gerçek SecLists karşılığı (referans) |
|---|---|---|
| `common.txt` | 85 satır | `raft-medium-directories.txt` ~30.000 satır |
| `apache.txt` | 14 satır | Apache'ye özel gerçek liste yüzlerce satır olur |
| `jenkins.txt` | 20 satır | Jenkins path listesi gerçekte çok daha kapsamlı |
| `wordpress.txt` | 17 satır | Gerçek WP plugin/tema listesi binlerce satır |
| `sensitive.txt` | 60 satır | Makul ama yine de küçük |
| `subdomains.txt` | 57 satır | Gerçek subdomain listeleri 100.000+ satır olabilir |

Yani `service_wordlist_map.yaml`'daki eşleştirme **mantığı** (servise göre wordlist seçme) doğru ve iyi yazılmış — asıl sorun bu değil. Sorun, arkasındaki **verinin** planladığımız gibi SecLists GitHub reposundan gelmiyor olması. Bu yüzden tarama sonuçların gerçekte olduğundan çok daha az bulgu üretecek (14-85 satırlık bir listeyle ciddi bir dizin taraması yapılamaz).

**Ek sorun — akıllı eşleştirme sadece pipeline modunda çalışıyor:**
`cmd/dirfuzz.go` dosyasına baktım — bağımsız `dirfuzz` komutu çalıştırıldığında (`specter-recon dirfuzz <url>`), `SelectWordlistForService` (akıllı servis-bazlı seçim) **hiç çağrılmıyor**. Sadece `--wordlist` flag'iyle verilen tek bir dosya kullanılıyor. Akıllı eşleştirme yalnızca `scan`/`fullscan` tam pipeline'ında devrede. README bunu "headline özellik" olarak tanıtıyor ama bağımsız komutta çalışmıyor — bu tutarsızlık kullanıcıyı yanıltır.

**Nasıl düzeltilir:**
1. **Gerçek SecLists'i submodule olarak ekle:**
   ```bash
   git submodule add https://github.com/danielmiessler/SecLists.git wordlists/SecLists
   ```
2. `service_wordlist_map.yaml`'daki yolları gerçek SecLists yol yapısına güncelle, örn:
   ```yaml
   jenkins: "wordlists/SecLists/Discovery/Web-Content/CMS/Jenkins.fuzz.txt"
   apache: "wordlists/SecLists/Discovery/Web-Content/Apache.fuzz.txt"
   wordpress: "wordlists/SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt"
   default: "wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
   ```
   (Not: bu dosya adları SecLists reposunun güncel yapısına göre kontrol edilip düzeltilmeli, repo zaman zaman yeniden organize ediliyor.)
3. Kendi elle yazdığın `sensitive.txt` gibi küçük dosyaları **tamamen atma** — bunlar hızlı/hafif bir "quick scan" modu için hâlâ işe yarar. İki seviyeli bir sistem kur: `--wordlist-size quick|full` gibi bir flag ile kullanıcı hızlı (senin küçük listelerin) veya kapsamlı (SecLists) mod seçebilsin.
4. `cmd/dirfuzz.go`'yu düzelt — bağımsız komut da `SelectWordlistForService`'i çağırsın (hedef URL'den servis tespiti yapılamıyorsa önce hızlı bir banner grab dener, ya da kullanıcı `--service jenkins` gibi bir flag ile manuel belirtebilir).

---

## 🟡 Komutlar Aşırı Karmaşık (senin 1. maddendeki şikayet — haklısın)

**Gözlem:** `scan` komutu tek başına 9 flag taşıyor:

```
--ports/-p, --threads/-t, --delay/-d, --subdomains, --skip-dirfuzz,
--skip-vuln, --output-dir/-o, --profile (web|network|ad|database|ssl|cloud|full), --authorized
```

Toplamda proje **14 ayrı komut** (`scan`, `fullscan`, `dns`, `discover`, `portscan`, `banner`, `vuln`, `dirfuzz`, `report`, `smb`, `ssl`, `creds`, `shell`, `root`) ve **22 modül** içeriyor. Bizim orijinal planımız 6-7 moduldü (DNS, Discovery, Portscan, Banner, CVE, Dirfuzz, Report). Proje bu aradan SNMP brute-force, LDAP/AD enum, SMB audit, FTP audit, SMTP audit, container/cloud audit, default credential brute-force gibi **tamamen yeni ve kapsamlı** modüller kazanmış.

**Bu iki ayrı sorunu işaret ediyor:**

1. **Kullanılabilirlik sorunu (senin bahsettiğin):** Yeni başlayan biri `--profile database` ile `--skip-vuln` arasındaki farkı, ya da 9 flag'in hangi sırayla/kombinasyonla kullanılacağını akılda tutamaz.
2. **Kapsam sorunu (bonus tespit):** Proje artık sadece "recon" değil, SNMP community string brute-force ve default credential deneme gibi **aktif saldırı/exploitation** kategorisine giren özellikler de içeriyor. Bu, orijinal "keşif aracı" fikrinden önemli ölçüde uzaklaşmış — hem karmaşıklığı hem de etik/yasal risk yüzeyini büyütüyor.

**Nasıl düzeltilir:**

- **Basit komutlar için:** `scan` komutunu 3 seviyeye indir:
  ```
  specter-recon scan <hedef>              # varsayılan: DNS+discovery+port+banner+dirfuzz+rapor (en yaygın kullanım)
  specter-recon scan <hedef> --quick      # sadece port+banner, hızlı sonuç
  specter-recon scan <hedef> --deep       # tüm genişletilmiş modülleri de çalıştırır (mevcut --profile full)
  ```
  Detaylı flag'ler (`--ports`, `--threads`, `--delay`) kalsın ama **hepsi opsiyonel ve makul varsayılanlarla** çalışsın — kullanıcı hiçbir flag yazmadan sadece `specter-recon scan example.com` diyebilmeli.
- **Profil karmaşıklığını azalt:** `--profile web|network|ad|database|ssl|cloud|full` yerine 2 seçenek yeterli: `--profile basic` (bizim orijinal 6 modül) / `--profile extended` (tüm ek denetimler). 7 seçenekli bir enum, komut satırında ezberlenemez.
- **Kapsam kararını netleştir:** SNMP/credential brute-force gibi modülleri ayrı bir alt-komut grubuna taşı (`specter-recon audit smb`, `specter-recon audit creds` gibi), varsayılan `scan` akışına dahil etme. Böylece "ben sadece keşif yapmak istiyorum" diyen kullanıcı yanlışlıkla brute-force gibi daha agresif/riskli bir işlem tetiklemez.
- **Yardım metnini iyileştir:** Her komutun `--help` çıktısında 1-2 örnek kullanım satırı olsun (cobra bunu `Example:` alanıyla destekliyor, şu an kullanılmamış).

---

## 🟢 Küçük / Kozmetik Sorunlar

- **`gofmt` formatlama uyarıları** — şu dosyalar Go standart formatına uymuyor (fonksiyonel hata değil ama derleme öncesi düzeltilmeli):
  `cmd/report.go`, `cmd/root.go`, `core/logger.go`, `core/models.go`, `core/storage.go`, `modules/dirfuzz.go`, `modules/nfs.go`, `modules/snmp.go`
  Düzeltmesi tek komut: `gofmt -w .`
- **JSON alan isimlendirmesi** planımızdaki `port_name`/`port_description`/`service_detay` yerine kodda `service_name`/`service_description`/`service_version` kullanılmış. Fonksiyonel bir sorun değil (aslında daha temiz bir isimlendirme) ama plan dosyalarınla kod arasında tutarsızlık var — hangisini referans alacağını netleştir.

---

## ✅ Yapılacaklar Listesi (TODO)

| # | Görev | Öncelik | Dosya(lar) |
|---|---|---|---|
| 1 | `authorizedFlag = true` satırını `cmd/shell.go`'dan kaldır, shell'de her komuttan önce izin sorusu sorulacak şekilde yeniden yaz | 🔴 Kritik | `cmd/shell.go` |
| 2 | Aktif deneme/exploitation modüllerini tamamen kaldır (bkz. yukarıdaki "Silinecek Dosyalar" listesi) | 🔴 Kritik | 10 modül + 2 cmd dosyası |
| 3 | SecLists'i gerçek git submodule olarak ekle, `service_wordlist_map.yaml`'ı gerçek yol yapısına güncelle | 🔴 Kritik | `wordlists/`, `.gitmodules`, `service_wordlist_map.yaml` |
| 4 | Bağımsız `dirfuzz` komutuna da akıllı wordlist seçimini bağla (`--service` flag'i veya otomatik tespit ile) | 🟡 Orta | `cmd/dirfuzz.go` |
| 5 | `--profile` sistemini tamamen kaldır, `scan` komutunu temel pipeline + opsiyonel `--extended` (ssl/ssh/http audit) şeklinde sadeleştir | 🟡 Orta | `cmd/scan.go`, `cmd/fullscan.go` |
| 6 | `core/models.go`, `core/storage.go`, `core/logger.go`, `modules/report.go`, `templates/report.html.tmpl` içindeki kaldırılan modüllere ait struct/fonksiyon/HTML bloklarını temizle | 🟡 Orta | ilgili dosyalar |
| 7 | `modules/modules_test.go`'dan kaldırılan modüllere ait testleri sil | 🟡 Orta | `modules/modules_test.go` |
| 8 | README'yi gerçek (recon-odaklı) kapsamı yansıtacak şekilde sadeleştir | 🟡 Orta | `README.md` |
| 9 | `GrabRawSocketBanner`'daki FTP/SMTP probe karışıklığını düzelt (FTP'ye `EHLO` yerine boş bırak ya da `SYST`) | 🟢 Düşük | `modules/banner.go` |
| 10 | MySQL/MariaDB versiyon regex'ini binary protokolü hesaba katacak şekilde iyileştir | 🟢 Düşük | `modules/banner.go` |
| 11 | Her komuta `Example:` alanı ekle (cobra'nın help çıktısında örnek kullanım gösterir) | 🟢 Düşük | tüm `cmd/*.go` |
| 12 | `gofmt -w .` çalıştırıp formatlama uyarılarını temizle | 🟢 Düşük | listelenen 8 dosya |
| 13 | Kendi makinende `go build ./...` çalıştırıp tam derleme hatası olup olmadığını doğrula (sandbox'ta ağ kısıtı nedeniyle tam test edilemedi) | 🟢 Düşük | tüm proje |
| 14 | Plan dosyalarındaki (`proje-plani.md`) alan isimlerini kodla tutarlı hale getir ya da kodu plana göre güncelle | 🟢 Düşük | `proje-plani.md`, `core/models.go` |

---

## Genel Değerlendirme

Kodun büyük kısmı (goroutine kullanımı, JSON modelleri, NVD API entegrasyonu, HTML rapor motoru, banner grabbing) **teknik olarak sağlam ve iyi yazılmış** — bu iyi haber. Asıl iki sorun tam senin işaret ettiğin yerlerde çıktı: **wordlist/SecList entegrasyonu gerçekte yok**, ve **komutlar gerçekten fazla karmaşık**. Bunlara ek olarak kod okurken bulduğum, senin sormadığın ama önemli bir güvenlik açığı da var (shell modunda izin onayının atlanması) — bunu öncelikli olarak düzeltmeni öneririm çünkü bu tam bizim en başta özellikle önemsediğimiz "yetkisiz tarama yapılmasın" guardrail'ini boşa çıkarıyor.

---

## 🔴 EK KARAR — Proje Kapsamı Recon'a Geri Çekiliyor

v2.0.0 README'sinde proje "130+ kontrollük evrensel güvenlik tarama motoru" haline gelmiş — SMB null session testi, Redis/Mongo NOAUTH erişim denemesi, default credential testing, LDAP anonymous bind, SNMP brute-force gibi modüller eklenmiş. Bunlar **pasif bilgi toplama değil, aktif erişim/exploitation denemesi** — orijinal "recon aracı" amacının tamamen dışında.

**Karar (senin onayınla):** Proje orijinal kapsamına geri çekiliyor — sadece DNS/port/banner/dirfuzz/CVE bilgisi toplayan bir recon aracı. Aktif deneme yapan tüm modüller kaldırılıyor.

### Modül Sınıflandırması

Her modülün kodunu kontrol ederek 3 kategoriye ayırdım:

| Kategori | Modüller | Karar |
|---|---|---|
| **✅ Çekirdek Recon (kalıyor)** | `dns_enum.go`, `discovery.go`, `portscan.go`, `banner.go`, `vulnmatch.go`, `dirfuzz.go`, `report.go` | Değişiklik yok — bunlar zaten planımızdaki 6-7 modül |
| **🟡 Pasif Genişletilmiş Bilgi (opsiyonel, kalabilir)** | `ssl_tls.go` (sertifika/protokol okuma), `ssh_audit.go` (SSH banner/algoritma okuma), `http_audit.go` (HTTP header okuma) | Kod incelendi — bunlar sadece bağlanıp veri **okuyor**, hiçbir kimlik doğrulama denemesi veya exploit yok. `--extended` gibi opsiyonel bir flag arkasına konup varsayılan taramaya dahil edilmeyebilir, ama zorunlu değil |
| **🔴 Aktif Deneme / Exploitation (kaldırılıyor)** | `creds.go`, `smb.go`, `db_enum.go`, `ftp_enum.go`, `snmp.go`, `ldap.go`, `nfs.go`, `iot.go`, `container.go`, `webvuln.go` | Bunların hepsi gerçek bir erişim/kimlik doğrulama denemesi yapıyor (default şifre deneme, auth'suz veri okuma, anonymous bind, XSS/SQLi enjeksiyon testi vb.) — recon kapsamının dışında, kaldırılmalı |

### Silinecek Dosyalar

```
modules/creds.go
modules/smb.go
modules/db_enum.go
modules/ftp_enum.go
modules/snmp.go
modules/ldap.go
modules/nfs.go
modules/iot.go
modules/container.go
modules/webvuln.go

cmd/creds.go
cmd/smb.go
```

### Düzenlenmesi Gereken Dosyalar

| Dosya | Ne yapılmalı |
|---|---|
| `cmd/scan.go` | `--profile web\|network\|ad\|database\|cloud\|full` seçeneklerini tamamen kaldır. Profil sistemi yerine tek bir sade akış kalsın: temel pipeline + opsiyonel `--extended` (ssl/ssh/http audit dahil etmek için) |
| `cmd/fullscan.go` | Artık "full" bir profil kavramı kalmadığı için bu komutu ya kaldır ya da `scan --extended`'ın kısayolu yap |
| `core/models.go` | `SmbFinding`, `FtpFinding`, `SnmpFinding`, `DbFinding`, `CredFinding`, `ContainerFinding`, `LdapFinding` struct'larını kaldır |
| `core/storage.go`, `core/logger.go` | Kaldırılan modüllere ait `Print*Table`, `Save*` fonksiyonlarını temizle |
| `modules/report.go` | HTML rapor şablonundan kaldırılan modüllere ait bölümleri çıkar |
| `templates/report.html.tmpl` | Aynı şekilde ilgili HTML bloklarını temizle |
| `modules/modules_test.go` | Kaldırılan modüllere ait testleri sil |
| `README.md` | v2.0.0 metnini gerçek kapsamı yansıtacak şekilde sadeleştir — "130+ kontrol" yerine net bir "recon pipeline" tanımı |

Bu temizlik aynı zamanda 🟡 **Komutlar Aşırı Karmaşık** maddesindeki sorunu da büyük ölçüde çözüyor — 14 komuttan geriye `scan`, `dns`, `discover`, `portscan`, `banner`, `vuln`, `dirfuzz`, `report`, `ssl` (opsiyonel), `shell` kalır ve `--profile` karmaşası tamamen ortadan kalkar.

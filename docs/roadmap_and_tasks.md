# SpecterRecon — Yol Haritası ve Görev Takip Dokümanı

**Son güncelleme:** 28 Ağustos 2026  
**Durum:** Tamamlandı (%100)

---

## 📌 Tamamlanan Temel Görevler

- [x] **Repo Güvenliği & Hijyeni:** `.gitignore` dosyası `output/`, loglar, derlenmiş binary'ler (`*.exe`, `specter-recon`) ve environment/secret dosyalarını içerecek şekilde güçlendirildi.
- [x] **Go Sürüm Standardizasyonu:** `go.mod` ve `README.md` Go sürüm bildirimleri (`Go 1.21+`) senkronize edildi.
- [x] **Lisans ve Katkı Rehberi:** `LICENSE` (MIT) ve `CONTRIBUTING.md` dosyaları repo köküne eklendi.
- [x] **CI/CD Pipeline:** Multi-OS (Linux, Windows, macOS) GitHub Actions (`.github/workflows/ci.yml`) iş akışı kuruldu.
- [x] **Nmap & Masscan Entegrasyonu v2:**
  - Seviye 1: `nmap -oX` (XML) ve `masscan -oJ` (JSON) içe aktarma ayrıştırıcıları.
  - Seviye 2: Masscan subprocess çalıştırıcı ve root/capability (`setcap`) rehberliği.
  - Seviye 3: Servis bazlı otomatik Nmap NSE zafiyet denetimi (`config.yaml` haritalı).
  - Port Doğrulama & Çelişki Katmanı: Masscan sonuçlarını native TCP handshake ile teyit eden ve çelişkileri şeffaf raporlayan katman.
  - Tarama Profilleri: `--profile aggressive | balanced | stealth`.
- [x] **Web Fuzzing False Positive Önleme:** 3 rastgele yol ile Catch-All / Soft-404 baseline tespiti, dinamik frekans filtreleme ve 429 adaptif backoff.
- [x] **WAF & CDN Tespiti:** AkamaiGHost, Cloudflare, AWS CloudFront, Imperva, F5 tespiti ve zorunlu `Host` header mimarisi.
- [x] **Raporlama:** Modern HTML SOC Dashboard (`output/report.html`), detaylı konsol tabloları ve özet dosyaları (`output/summary.txt`).

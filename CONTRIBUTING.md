# Katkı ve Geliştirme Rehberi (Contributing Guidelines)

**SpecterRecon** projesine gösterdiğiniz ilgi için teşekkür ederiz.

## 📌 Genel İlkeler

1. **Güvenlik ve Etik Sorumluluk:**
   - SpecterRecon kesinlikle bir saldırı/istismar (exploit payload) aracı değil, **defansif ağ keşfi ve zafiyet görünürlüğü** motorudur.
   - Projeye hedef sistemlere zarar verici veya izinsiz sömürü sağlayan kod eklenemez.

2. **Dış Katkılar (Pull Requests & Issues):**
   - Otomatik yapay zeka ajanları veya botlar tarafından açılan kontrolsüz PR'lar güvenlik ve repo hijyeni nedeniyle doğrudan kapatılır.
   - Hata bildirimleri (Bug Reports) veya özellik önerileri için lütfen detaylı açıklama içeren bir Issue açınız.
   - Kod katkısı yapmadan önce lütfen bir Issue üzerinden tartışma başlatınız.

3. **Kodlama Standartları:**
   - Tüm yeni modüller için `modules/modules_test.go` içine unit test yazılmalıdır.
   - Kod `go vet ./...` ve `go test -v ./...` kontrollerinden sıfır hata ile geçmelidir.
   - Harici Cgo veya C kütüphanesi bağımlılığı eklenmemeli, Go native sıfır-bağımlılık (zero-dependency) mimarisi korunmalıdır.

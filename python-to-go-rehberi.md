# Python → Go Dönüşüm Rehberi (Recon/Tarama Aracı)

Bu rehber, önceki planda tanımlanan modülleri Python'dan Go'ya taşırken kullanacağın kütüphane karşılıklarını, dikkat edilmesi gereken dil farklarını ve modül modül yol haritasını içerir.

---

## 1. Kütüphane / Araç Karşılıkları

| Amaç | Python | Go Karşılığı |
|---|---|---|
| CLI framework | `typer` / `argparse` | `cobra` veya `urfave/cli` |
| Terminal UI (progress bar, renk, tablo) | `rich` | `pterm` (kolay) veya `bubbletea` (gelişmiş/interaktif) |
| Async/concurrency | `asyncio` | Native `goroutine` + `channel` + `sync.WaitGroup` |
| Raw socket / ARP / ICMP | `scapy` | `gopacket` + `gopacket/pcap` (libpcap gerekir) |
| TCP connect scan | `socket` (blocking/async) | `net.Dial` + goroutine pool |
| HTTP istekleri (banner/dir fuzz) | `httpx` / `aiohttp` | `net/http` (standart kütüphane yeterli, `http.Client` + timeout) |
| JSON okuma/yazma | `json` modülü | `encoding/json` (struct tag'leriyle) |
| Veri modeli/validasyon | `pydantic` / `dataclass` | Native `struct` (validasyon için `go-playground/validator` opsiyonel) |
| Config dosyası (YAML) | `pyyaml` | `gopkg.in/yaml.v3` |
| Loglama | `logging` | `log/slog` (Go 1.21+, yapılandırılmış log) |
| HTML rapor (template) | `jinja2` | `html/template` (standart kütüphane) |
| Concurrency sınırlama (semaphore) | `asyncio.Semaphore` | Buffered channel (`make(chan struct{}, N)`) veya `golang.org/x/sync/semaphore` |
| Regex (banner/versiyon parse) | `re` | `regexp` (standart, syntax RE2 — bazı Python regex'leri birebir çalışmayabilir) |
| NVD API için HTTP client | `requests` | `net/http` |

---

## 2. Dil Farkları — Dikkat Edilmesi Gerekenler

### Concurrency modeli tamamen farklı
Python'da `asyncio` ile yazdığın `async def` / `await` yapısı Go'da yok. Go'da concurrency **goroutine + channel** ile yapılır — "paylaşılan bellek yerine mesajlaşarak haberleş" mantığı. Örnek dönüşüm mantığı:

```python
# Python (asyncio)
async def scan_port(ip, port, sem):
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=1
            )
            writer.close()
            return port, True
        except:
            return port, False
```

```go
// Go
func scanPort(ip string, port int, sem chan struct{}, results chan<- PortResult, wg *sync.WaitGroup) {
    defer wg.Done()
    sem <- struct{}{}        // semaphore acquire
    defer func() { <-sem }() // semaphore release

    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 1*time.Second)
    if err != nil {
        results <- PortResult{Port: port, Open: false}
        return
    }
    conn.Close()
    results <- PortResult{Port: port, Open: true}
}
```

### Hata yönetimi
Python'da `try/except`, Go'da **explicit error return** var — her fonksiyon çağrısından sonra `if err != nil` kontrolü yazman gerekecek. Başta can sıkıcı gelir ama recon aracı gibi network hatalarının bol olduğu bir projede aslında avantaj — hangi adımda ne patladığını çok net görürsün.

### Struct + JSON tag'leri
Python'daki dataclass/pydantic modelin Go'da struct + tag olarak karşılık bulur:

```python
# Python
@dataclass
class ServiceInfo:
    port: int
    service_name: str
    service_version: str
    source_ip: str
```

```go
// Go
type ServiceInfo struct {
    Port           int    `json:"port"`
    ServiceName    string `json:"service_name"`
    ServiceVersion string `json:"service_version"`
    SourceIP       string `json:"source_ip"`
}
```

### Raw socket / ARP scan için root/admin + libpcap gerekir
`gopacket` kullanacaksan sistemde `libpcap-dev` (Linux) kurulu olmalı, ve program yine root/admin yetkisiyle çalıştırılmalı — bu kısıt Python/scapy'de de aynıydı, değişmiyor.

### Timeout ve context kullanımı
Go'da network işlemlerinde `context.Context` ile timeout/cancel yönetimi standarttır — Python'daki `asyncio.wait_for`'un karşılığı gibi düşün. Her modülün fonksiyonuna `ctx context.Context` parametresi geçirmeyi alışkanlık haline getir.

---

## 3. Modül Modül Dönüşüm Sırası

Önceki planı temel alarak, dönüşümü şu sırayla yapmanı öneririm (küçükten büyüğe, bağımsız test edilebilir parçalar halinde):

| Sıra | Modül | Python dosyan | Go karşılığı | Not |
|---|---|---|---|---|
| 1 | Veri modelleri | `core/models.py` | `core/models.go` | Önce struct'ları tanımla, her şey buna bağlı |
| 2 | JSON okuma/yazma | `core/storage.py` | `core/storage.go` | `encoding/json`, basit |
| 3 | CLI iskeleti | `main.py` | `main.go` + `cmd/` | `cobra` ile komut yapısını kur |
| 4 | Port scan | `modules/portscan.py` | `modules/portscan.go` | En çok performans farkı burada hissedilir |
| 5 | Banner grab | `modules/banner.py` | `modules/banner.go` | `net.Dial` + `bufio.Reader` |
| 6 | Host discovery (ARP/ICMP) | `modules/discovery.py` | `modules/discovery.go` | En zor kısım — `gopacket` öğrenme eğrisi var |
| 7 | Dir bruteforce | `modules/dirfuzz.py` | `modules/dirfuzz.go` | goroutine pool ile hızlı kazanç alacağın yer |
| 8 | CVE eşleştirme | `modules/vuln_match.py` | `modules/vuln_match.go` | Sadece HTTP client, kolay |
| 9 | Rapor üretimi | `modules/report.py` | `modules/report.go` | `html/template`, Jinja2'ye çok benzer syntax |

**Öneri**: 1-2-3'ü kurup iskeleti oturttuktan sonra, **4 (port scan)** ve **7 (dir bruteforce)**'a öncelik ver — Go'ya geçişin asıl sebebi olan performans kazancını burada göreceksin ve motivasyonun artar. Discovery (ARP/gopacket) en çetrefilli kısım, onu sona bırakabilirsin.

---

## 4. Yeni Proje İskeleti (Go)

```
recon-tool-go/
├── cmd/
│   └── root.go                # cobra kök komut
├── core/
│   ├── models.go
│   ├── storage.go
│   └── logger.go
├── modules/
│   ├── discovery.go
│   ├── portscan.go
│   ├── banner.go
│   ├── vulnmatch.go
│   ├── dirfuzz.go
│   └── report.go
├── templates/
│   └── report.html.tmpl
├── wordlists/
│   └── SecLists/               # git submodule (aynı kalır)
├── config.yaml
├── go.mod
├── go.sum
├── main.go
└── README.md
```

Kurulum başlangıcı:
```bash
go mod init github.com/kullaniciadi/recon-tool-go
go get github.com/spf13/cobra@latest
go get github.com/google/gopacket@latest
go get github.com/pterm/pterm@latest
go get gopkg.in/yaml.v3@latest
```

---

## 5. Beklenen Kazançlar (neden buna değer)

- Geniş IP aralığı + port range taramada gözle görülür hız artışı (goroutine overhead'i Python'un asyncio task overhead'inden çok daha düşük)
- Tek binary çıktı — `go build` sonrası tek dosya, Python runtime/pip bağımlılığı yok, farklı makinelere taşımak trivial
- Dir bruteforce modülünde binlerce eşzamanlı istek atarken bellek kullanımı Python'a göre çok daha düşük kalır

## 6. Kaybedeceğin Şeyler (dürüst olalım)

- `scapy`'nin sunduğu hazır paket manipülasyon kolaylığı yok — `gopacket` ile packet crafting biraz daha elle
- Hızlı prototipleme/deneme-yanılma Python kadar akıcı değil, derleme adımı var
- Kütüphane ekosistemi network security alanında Python kadar zengin değil (ama nmap/masscan/gobuster zaten Go/C, yani ana ihtiyaçların karşılanıyor)

---

## 7. Sıradaki Adım Önerisi

1. Go'yu kur, `go mod init` ile boş proje aç
2. `core/models.go`'yu yaz (Python'daki dataclass'ların birebir struct karşılığı)
3. Basit bir `portscan.go` ile tek bir IP'ye karşı goroutine tabanlı port tarama dene — bu sana Go'nun concurrency modelini en hızlı şekilde hissettirir
4. Buradan devam edip CLI iskeletini kurarız

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/pterm/pterm"
	"github.com/specter-recon/recon-tool/core"
	"github.com/spf13/cobra"
)

var (
	authorizedFlag       bool
	isInteractiveSession bool
	version              = "0.8.0"
)

// RootCmd is the base command for SpecterRecon.
var RootCmd = &cobra.Command{
	Use:          "specter-recon",
	Short:        "⚡ SpecterRecon — Yüksek Performanslı Modüler Ağ Keşif Motoru",
	SilenceUsage: true,
	Long: `
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

SpecterRecon — Siber güvenlik araştırmacıları, sızma testi ekipleri ve SOC analistleri
için geliştirilmiş, yüksek eşzamanlılıklı, modüler ve pipeline destekli recon motorudur.

Parametresiz çalıştırdığınızda interaktif konsol (Metasploit tarzı) moduna geçer.`,
	Example: `  specter-recon                                     → İnteraktif konsol modu
  specter-recon scan example.com --authorized        → Temel pipeline tarama
  specter-recon fullscan example.com --authorized    → Genişletilmiş tam denetim`,
	Run: func(cmd *cobra.Command, args []string) {
		StartInteractiveShell(cmd)
	},
}

func Execute() {
	RootCmd.SilenceUsage = true
	for _, c := range RootCmd.Commands() {
		c.SilenceUsage = true
	}
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().BoolVar(&authorizedFlag, "authorized", false, "Hedef için yasal tarama izninizin olduğunu onaylar")

	RootCmd.SetHelpTemplate(`
{{.Long}}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
KULLANIM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  {{.UseLine}}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚀  PIPELINE KOMUTLARI  (Tam otomatik keşif zinciri)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  scan <hedef> [bayraklar]
      DNS → Host Discovery → Port Scan → Banner Grab → DirFuzz
      pipeline'ını sırayla çalıştırır. En temel recon komutu.

      Bayraklar:
        -p, --ports           Port aralığı veya listesi (varsayılan: top-1000)
                              Örn: "80,443,8080"  "1-65535"  "top-100"
        -t, --threads         Eşzamanlı worker sayısı (varsayılan: 50)
        -d, --delay           İstekler arası gecikme ms cinsinden (varsayılan: 0)
            --subdomains      Subdomain brute-force'u aktif eder
            --skip-dirfuzz    Web dizin fuzzing adımını atlar
            --wordlist-size   Wordlist boyutu: quick | balanced | full (varsayılan: balanced)
                              quick   → ~300 kelime (hızlı tarama)
                              balanced→ ~3.000 kelime (varsayılan)
                              full    → ~30.000 kelime (SecLists tam liste)
            --profile         Tarama profili: balanced | aggressive | stealth
                              balanced   → Native Go worker pool, dengeli (varsayılan)
                              aggressive → Masscan + Nmap NSE + SecLists full list
                              stealth    → Düşük thread, yüksek gecikme, sessiz
            --extended        SSL/TLS + HTTP audit + SSH audit modüllerini çalıştırır
            --nmap-xml        Önceden alınmış nmap -oX çıktısını içe aktarır
            --masscan-json    Önceden alınmış masscan -oJ çıktısını içe aktarır
            --use-masscan     Masscan'ı subprocess olarak tetikler (root gerekli)
            --use-nmap-nse    Tespit edilen servislere Nmap NSE scriptleri uygular
        -o, --output          Çıktı dizini (varsayılan: ./output)
            --authorized      Yasal izin onayı (zorunlu)

      Örnekler:
        specter-recon scan example.com --authorized
        specter-recon scan example.com --subdomains --wordlist-size full --authorized
        specter-recon scan 10.0.0.0/24 --profile aggressive --authorized
        specter-recon scan example.com --profile stealth -d 200 --authorized
        specter-recon scan example.com --ports 1-65535 -t 200 --authorized
        specter-recon scan example.com --extended --authorized
        specter-recon scan --nmap-xml nmap_out.xml --authorized
        specter-recon scan --masscan-json masscan_out.json --authorized

  ─────────────────────────────────────────────────────────────────

  fullscan <hedef> [bayraklar]
      scan --extended kısayolu. SSL/TLS, HTTP güvenlik başlıkları,
      CORS, GraphQL ve SSH algoritma denetimleri dahil tam tarama.
      Scan'in tüm bayraklarını destekler.

      Örnekler:
        specter-recon fullscan example.com --authorized
        specter-recon fullscan example.com --subdomains --authorized
        specter-recon fullscan 192.168.1.0/24 --profile aggressive --authorized
        specter-recon fullscan example.com --wordlist-size full --authorized
        specter-recon fullscan example.com --use-nmap-nse --authorized

  ─────────────────────────────────────────────────────────────────

  shell
      Metasploit tarzı interaktif konsol moduna geçer.
      Ok tuşu geçmişi, TAB tamamlama, Ctrl+C/D destekler.
      Parametresiz çalıştırmakla aynıdır.

        specter-recon shell

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔬  BAĞIMSIZ MODÜLLER  (Tek adım çalıştırma)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  dns <hedef> [bayraklar]
      A, MX, NS, TXT, SRV, PTR DNS kayıtlarını çözer.
      --subdomains ile wordlist tabanlı subdomain brute-force yapar.
      Bulunan IP'ler için otomatik ters DNS (PTR) sorgusu yapar.

      Bayraklar:
        --subdomains    Subdomain brute-force aktif eder
        -t, --threads   Worker sayısı

      Örnekler:
        specter-recon dns example.com --authorized
        specter-recon dns example.com --subdomains --authorized
        specter-recon dns example.com --subdomains -t 100 --authorized

  ─────────────────────────────────────────────────────────────────

  discover <hedef> [bayraklar]
      ICMP Ping + TCP SYN Probe ile ağdaki canlı hostları tespit eder.
      Tek IP, CIDR aralığı veya host listesi destekler.

      Örnekler:
        specter-recon discover 192.168.1.0/24 --authorized
        specter-recon discover 10.0.0.1-254 --authorized
        specter-recon discover 10.0.0.100 --authorized

  ─────────────────────────────────────────────────────────────────

  portscan <hedef> [bayraklar]
      Yüksek hızlı TCP Connect port taraması. Native Go worker pool.
      CIDR, tek IP veya domain destekler.

      Bayraklar:
        -p, --ports     Port aralığı/listesi (varsayılan: top-1000)
        -t, --threads   Eşzamanlı worker sayısı (varsayılan: 50)

      Örnekler:
        specter-recon portscan 192.168.1.1 --authorized
        specter-recon portscan 10.0.0.100 -p 1-65535 -t 200 --authorized
        specter-recon portscan 10.0.0.0/24 -p 80,443,8080,8443 --authorized
        specter-recon portscan example.com -p top-100 --authorized

  ─────────────────────────────────────────────────────────────────

  banner <hedef:port> [bayraklar]
      Belirtilen IP:port veya domain:port çiftlerinden servis banner'ı
      ve versiyon bilgisi çeker. Protokol otomatik algılama yapar.

      Desteklenen protokoller:
        HTTP/HTTPS, SSH, FTP, SMTP, MySQL, MSSQL, LDAP, SMB2/NTLMSSP,
        RDP (TLS/NLA), WinRM/WSMAN, VNC (RFB), Redis, Memcached,
        PostgreSQL, Oracle TNS, NetBIOS, Kerberos, SIP, MSRPC

      Örnekler:
        specter-recon banner 192.168.1.1:80 --authorized
        specter-recon banner 10.0.0.100:445 --authorized
        specter-recon banner example.com:22 --authorized
        specter-recon banner 10.0.0.100:389 --authorized   (LDAP / AD)

  ─────────────────────────────────────────────────────────────────

  dirfuzz <url> [bayraklar]
      Akıllı web dizin ve dosya fuzzing. Tespit edilen servise göre
      otomatik uzantı ve wordlist seçimi yapar. robots.txt + sitemap
      keşfi, catch-all/wildcard filtresi, WAF/CDN tespiti içerir.

      Bayraklar:
        --service       Servis tipi: iis | apache | nginx | php |
                        springboot | wordpress | jenkins | tomcat
        --wordlist-size quick | balanced | full
        -t, --threads   Worker sayısı
        -x, --exts      Özel uzantı listesi: ".php,.bak,.conf"

      Örnekler:
        specter-recon dirfuzz http://example.com --authorized
        specter-recon dirfuzz http://10.0.0.100 --service iis --authorized
        specter-recon dirfuzz https://example.com --service wordpress --authorized
        specter-recon dirfuzz http://app.com --wordlist-size full --authorized
        specter-recon dirfuzz http://app.com -x ".php,.bak,.env" --authorized

  ─────────────────────────────────────────────────────────────────

  ssl <host:port> [bayraklar]
      SSL/TLS sertifika geçerliliği, SAN alanları, zayıf protokol
      (SSLv3, TLS 1.0/1.1) ve zayıf cipher suite denetimi yapar.
      HTTP güvenlik başlıkları (HSTS, CSP, X-Frame-Options vb.),
      CORS ve GraphQL endpoint denetimi de kapsar.

      Örnekler:
        specter-recon ssl example.com:443 --authorized
        specter-recon ssl 10.0.0.100:8443 --authorized
        specter-recon ssl 10.0.0.100:443 --authorized

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊  RAPORLAMA
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  report [bayraklar]
      Mevcut output/ klasöründeki JSON tarama sonuçlarından
      HTML dashboard ve summary.txt raporu üretir.

      Bayraklar:
        -t, --title   Rapor başlığı (varsayılan: "SpecterRecon Report")
        -o, --output  Çıktı dizini (varsayılan: ./output)

      Örnekler:
        specter-recon report --authorized
        specter-recon report -t "Milsoft Pentest" --authorized
        specter-recon report -o ./output/milsoft --authorized

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔗  DIŞ ARAÇ ENTEGRASYONları
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Masscan (Hızlı SYN Port Tarama — Root/Admin gerektirir):
    specter-recon scan 10.0.0.0/24 --use-masscan --authorized
    specter-recon scan 10.0.0.0/24 --masscan-json masscan_out.json --authorized

    Manuel masscan → import:
      sudo masscan 10.0.0.0/24 -p1-65535 --rate=50000 -oJ out.json
      specter-recon scan --masscan-json out.json --authorized

  Nmap NSE (Zafiyet Denetimi):
    specter-recon scan example.com --use-nmap-nse --authorized
    specter-recon scan --nmap-xml nmap_out.xml --authorized

    Manuel nmap → import:
      nmap -sV -p80,443,445 -oX out.xml example.com
      specter-recon scan --nmap-xml out.xml --authorized

    Yerleşik NSE eşlemeleri (config.yaml üzerinden özelleştirilebilir):
      Port 445  → smb-vuln-ms17-010, smb-os-discovery
      Port 443  → ssl-heartbleed, ssl-cert
      Port 80   → http-vuln-cve2021-41773, http-methods
      Port 22   → ssh-auth-methods
      Port 3389 → rdp-enum-encryption

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚡  HIZLI BAŞLANGIÇ ÖRNEKLERİ
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  # İnteraktif konsol (ok tuşu geçmişi + TAB tamamlama)
  specter-recon

  # Bir domain'i uçtan uca tara (DNS+Port+Banner+Web+SSL/HTTP/SSH)
  specter-recon fullscan example.com --authorized

  # Subdomain keşfi dahil tam tarama + derin wordlist
  specter-recon fullscan example.com --subdomains --wordlist-size full --authorized

  # Tüm portları tara (1-65535), aggressive modda
  specter-recon scan example.com -p 1-65535 --profile aggressive --authorized

  # İç ağ taraması (CIDR) — stealth modda
  specter-recon scan 10.0.0.0/24 --profile stealth --authorized

  # Sadece IIS'e özel dizin fuzzing
  specter-recon dirfuzz http://10.0.0.100 --service iis --wordlist-size full --authorized

  # SSL sertifika ve güvenlik başlığı denetimi
  specter-recon ssl example.com:443 --authorized

  # Önceki taramadan rapor üret
  specter-recon report -t "Müşteri Pentest Raporu" --authorized

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GLOBAL BAYRAKLAR
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}

  Detaylı modül yardımı: specter-recon [komut] --help
  Örn: specter-recon scan --help
`)
}

func verifyScopePermission(target string) bool {
	if authorizedFlag {
		return true
	}

	pterm.Println()
	pterm.DefaultBox.WithTitle("YASAL UYARI & GÜVENLİK GUARDRAIL'I").
		WithBoxStyle(pterm.NewStyle(pterm.FgYellow, pterm.Bold)).
		Println(fmt.Sprintf("Bu araç yalnızca yetkili olduğunuz sistemler (lab, CTF, izinli pentest) içindir.\nHedef: %s", target))

	fmt.Print("\nBu hedefi taramak için yasal izniniz olduğunu onaylıyor musunuz? (e/H): ")
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))

	if answer != "e" && answer != "y" && answer != "evet" && answer != "yes" {
		core.LogError("Kullanıcı izni onaylamadı. İşlem durduruldu.")
		if !isInteractiveSession {
			os.Exit(1)
		}
		return false
	}
	return true
}

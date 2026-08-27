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
	version              = "1.0.0"
)

// RootCmd is the base command for SpecterRecon.
var RootCmd = &cobra.Command{
	Use:   "specter-recon",
	Short: "⚡ SpecterRecon: Yüksek Performanslı ve Modüler Ağ Keşif (Recon) Motoru",
	Long: `SpecterRecon, siber güvenlik araştırmacıları, sızma testi ekipleri ve SOC analistleri için
geliştirilmiş, yüksek eşzamanlılıklı (Goroutine Worker Pools), modüler ve tam boru hattı
(pipeline) destekli yeni nesil ağ keşif (reconnaissance) motorudur.

Çekirdek Keşif Modülleri:
  • DNS & Subdomain Keşfi (Brute-Force & Reverse DNS)
  • Çok Yöntemli Canlı Host Keşfi (ARP, ICMP Ping, TCP SYN Probe)
  • Goroutine Destekli Hızlı TCP Connect Port Taraması
  • Protokol ve Banner Ayrıştırma (HTTP, SSH, MySQL, NetBIOS, VNC, FTP, SMTP)
  • Servise Özel Akıllı Web Dizin Fuzzing (SecLists Submodule Entegrasyonu)

Genişletilmiş Pasif Denetim Modülleri (--extended):
  • SSL/TLS Sertifika Geçerlilik, SAN ve Zayıf Protokol Denetimi
  • HTTP Güvenlik Başlıkları (Security Headers), CORS ve GraphQL Denetimi
  • SSH Algoritma ve Güvenlik Konfigürasyon Denetimi`,
	Example: `  # 1. İnteraktif Konsol Modu (Parametresiz Çalıştırma):
  specter-recon

  # 2. Temel Boru Hattı Keşif Taraması (DNS + Discovery + Port + Banner + Web):
  specter-recon scan example.com --authorized

  # 3. Subdomain Brute-Force ve Genişletilmiş Denetimlerle Tam Tarama:
  specter-recon fullscan example.com --subdomains --authorized

  # 4. SecLists ile Kapsamlı (30,000+ kelime) Web Dizin Taraması:
  specter-recon scan example.com --wordlist-size full --authorized

  # 5. Bağımsız Özel Port ve Thread Ayarlı Tarama:
  specter-recon portscan 192.168.1.1 -p 1-1024 -t 100 --authorized

  # 6. Servis Bazlı Akıllı Web Fuzzing (IIS, Nginx, Apache, Jenkins, WordPress):
  specter-recon dirfuzz http://example.com --service iis --authorized`,
	Run: func(cmd *cobra.Command, args []string) {
		StartInteractiveShell(cmd)
	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().BoolVar(&authorizedFlag, "authorized", false, "Hedef için yasal tarama izninizin olduğunu onaylar (Guardrail Onayı)")

	// Custom categorized help template
	RootCmd.SetHelpTemplate(`
{{.Long}}

KULLANIM (USAGE):
  {{.UseLine}}
{{if .HasAvailableSubCommands}}
KOMUT KATEGORİLERİ:
  🚀 Keşif Pipeline Komutları:
    scan        Hedef üzerinde tam otomatik DNS + Host + Port + Banner + Web pipeline'ı çalıştırır
    fullscan    Tüm çekirdek ve genişletilmiş modülleri (SSL/HTTP/SSH) aktif ederek çalıştırır (scan --extended kısayolu)
    shell       Metasploit tarzı interaktif konsol modunu başlatır

  🔬 Bağımsız Keşif & Analiz Modülleri:
    dns         Hedef domain için DNS çözümleme ve subdomain brute-force yapar
    discover    Ağdaki canlı hostları tespit eder (ICMP / TCP Ping)
    portscan    Hedefte yüksek hızlı TCP port taraması yapar
    banner      Açık portlardan servis ve temiz versiyon banner'ı çeker
    dirfuzz     Akıllı wordlist ve SecLists ile web dizin/dosya fuzzing yapar
    ssl         SSL/TLS sertifika geçerliliği ve zayıf protokol denetimi yapar

  📊 Raporlama & Yardımcılar:
    report      Mevcut JSON tarama çıktılarından HTML dashboard ve summary.txt üretir
    help        Herhangi bir komut hakkında detaylı yardım gösterir
{{end}}
{{if .HasAvailableLocalFlags}}BAYRAKLAR (FLAGS):
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
{{end}}
{{if .HasAvailableInheritedFlags}}GLOBAL BAYRAKLAR:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}
{{end}}
{{if .Example}}ÖRNEKLER (EXAMPLES):
{{.Example}}
{{end}}
Detaylı modül yardımı için: specter-recon [komut] --help
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

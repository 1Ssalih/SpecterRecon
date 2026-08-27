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
	Short: "SpecterRecon: Yüksek Performanslı ve Modüler Ağ Keşif (Recon) Motoru",
	Long: `SpecterRecon, siber güvenlik araştırmacıları ve sızma testi ekipleri için
geliştirilmiş, yüksek eşzamanlılıklı (Goroutine), modüler ve tam pipeline destekli
ağ keşif (reconnaissance) aracıdır.

Çekirdek modüller: DNS Enumeration, Host Discovery, Port Scan, Banner Grabbing
ve Web Directory Fuzzing (Akıllı Wordlist / SecLists).

Opsiyonel genişletilmiş modüller (--extended): SSL/TLS Audit, HTTP Security Audit,
SSH Konfigürasyon Audit.`,
	Example: `  # İnteraktif Shell konsoluna gir
  specter-recon

  # Hedef üzerinde tam keşif pipeline'ı çalıştır
  specter-recon scan example.com --authorized

  # Genişletilmiş audit modülleri ile çalıştır (SSL + HTTP + SSH)
  specter-recon fullscan example.com --authorized

  # SecLists ile derin web dizin taraması
  specter-recon dirfuzz http://example.com --wordlist-size full --authorized`,
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
	RootCmd.PersistentFlags().BoolVar(&authorizedFlag, "authorized", false, "Hedef için yasal tarama izninizin olduğunu onaylar")
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

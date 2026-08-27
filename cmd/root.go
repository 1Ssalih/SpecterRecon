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
	authorizedFlag bool
	version        = "1.0.0"
)

// RootCmd is the base command for SpecterRecon.
var RootCmd = &cobra.Command{
	Use:   "specter-recon",
	Short: "SpecterRecon: Yüksek Performanslı Ağ Keşif (Recon) ve Zafiyet Analiz Motoru",
	Long: `SpecterRecon, siber güvenlik araştırmacıları ve sızma testi ekipleri için
geliştirilmiş, yüksek eşzamanlılıklı (Goroutine), modüler ve tam pipeline destekli
ağ keşif (reconnaissance) ve zafiyet analiz aracıdır.

Çekirdek modüller: DNS Enumeration, Host Discovery, Port Scan, Banner Grabbing,
CVE Matching ve Web Directory Fuzzing.

Opsiyonel genişletilmiş modüller (--extended): SSL/TLS Audit, HTTP Security Audit,
SSH Konfigürasyon Audit.`,
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

func verifyScopePermission(target string) {
	if authorizedFlag {
		return
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
		os.Exit(1)
	}
}

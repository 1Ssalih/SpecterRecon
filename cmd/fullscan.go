package cmd

import (
	"github.com/spf13/cobra"
)

var fullscanCmd = &cobra.Command{
	Use:   "fullscan [target]",
	Short: "Tüm recon adımlarını ve genişletilmiş modülleri dahil tam tarama modunda çalıştırır (scan --extended kısayolu)",
	Example: `  # Tam kapsamlı recon taraması
  specter-recon fullscan scanme.nmap.org --authorized

  # Subdomain brute-force dahil
  specter-recon fullscan example.com --subdomains --authorized`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		extendedFlag = true
		scanCmd.Run(cmd, args)
	},
}

func init() {
	fullscanCmd.Flags().StringVarP(&portsFlag, "ports", "p", "top-100", "Taranacak portlar")
	fullscanCmd.Flags().IntVarP(&threadsFlag, "threads", "t", 50, "Eşzamanlı bağlantı limiti")
	fullscanCmd.Flags().IntVarP(&delayFlag, "delay", "d", 0, "İstekler arası gecikme (ms) — Stealth modu")
	fullscanCmd.Flags().BoolVar(&subdomainsFlag, "subdomains", false, "Subdomain brute-force")
	fullscanCmd.Flags().BoolVar(&skipDirfuzzFlag, "skip-dirfuzz", false, "Dizin fuzzing adımını atla")
	fullscanCmd.Flags().StringVarP(&outputDirFlag, "output-dir", "o", "output", "Çıktı klasörü")
	fullscanCmd.Flags().StringVar(&wordlistSizeFlag, "wordlist-size", "quick", "Wordlist boyutu: 'quick' veya 'full' (SecLists)")
	fullscanCmd.Flags().StringVar(&profileFlag, "profile", "balanced", "Tarama profili: 'aggressive' (Masscan+NSE), 'balanced' (Varsayılan), 'stealth' (Sessiz)")
	fullscanCmd.Flags().StringVar(&nmapXMLFlag, "nmap-xml", "", "İçe aktarılacak Nmap XML çıktı dosyası (-oX)")
	fullscanCmd.Flags().StringVar(&masscanJSONFlag, "masscan-json", "", "İçe aktarılacak Masscan JSON çıktı dosyası (-oJ)")
	fullscanCmd.Flags().BoolVar(&useMasscanFlag, "use-masscan", false, "Masscan ile port taraması çalıştırır (Root/Admin gerektirir)")
	fullscanCmd.Flags().BoolVar(&useNmapNSEFlag, "use-nmap-nse", false, "Tespit edilen servislere özel Nmap NSE zafiyet scriptlerini çalıştırır")

	RootCmd.AddCommand(fullscanCmd)
}

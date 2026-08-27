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
	fullscanCmd.Flags().BoolVar(&subdomainsFlag, "subdomains", false, "Subdomain brute-force")
	fullscanCmd.Flags().StringVarP(&outputDirFlag, "output-dir", "o", "output", "Çıktı klasörü")
	fullscanCmd.Flags().StringVar(&wordlistSizeFlag, "wordlist-size", "quick", "Wordlist boyutu: 'quick' veya 'full' (SecLists)")

	RootCmd.AddCommand(fullscanCmd)
}

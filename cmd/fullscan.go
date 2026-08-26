package cmd

import (
	"github.com/spf13/cobra"
)

var fullscanCmd = &cobra.Command{
	Use:   "fullscan [target]",
	Short: "Tüm pentest adımlarını ve modüllerini eksiksiz tam tarama modunda çalıştırır",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		profileFlag = "full"
		scanCmd.Run(cmd, args)
	},
}

func init() {
	fullscanCmd.Flags().StringVarP(&portsFlag, "ports", "p", "top-100", "Taranacak portlar")
	fullscanCmd.Flags().IntVarP(&threadsFlag, "threads", "t", 50, "Eşzamanlı bağlantı limiti")
	fullscanCmd.Flags().BoolVar(&subdomainsFlag, "subdomains", false, "Subdomain brute-force")
	fullscanCmd.Flags().StringVarP(&outputDirFlag, "output-dir", "o", "output", "Çıktı klasörü")

	RootCmd.AddCommand(fullscanCmd)
}

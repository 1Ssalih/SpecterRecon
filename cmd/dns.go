package cmd

import (
	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

var (
	dnsSubdomainsFlag bool
	dnsWordlistFlag   string
	dnsOutputFlag     string
	dnsThreadsFlag    int
)

var dnsCmd = &cobra.Command{
	Use:   "dns [domain]",
	Short: "Hedef domain için DNS Enumeration ve opsiyonel Subdomain Brute-Force yapar",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		core.PrintBanner(version)
		verifyScopePermission(target)

		findings, _, _ := modules.EnumerateDNS(
			target,
			dnsSubdomainsFlag,
			dnsWordlistFlag,
			dnsThreadsFlag,
			dnsOutputFlag,
		)
		core.PrintDNSTable(findings)
	},
}

func init() {
	dnsCmd.Flags().BoolVar(&dnsSubdomainsFlag, "subdomains", false, "Subdomain brute-force keşfini aktif eder")
	dnsCmd.Flags().StringVarP(&dnsWordlistFlag, "wordlist", "w", "wordlists/subdomains.txt", "Subdomain brute-force wordlist yolu")
	dnsCmd.Flags().StringVarP(&dnsOutputFlag, "output", "o", "output/ip_list.json", "Çıktı IP listesi JSON dosyası")
	dnsCmd.Flags().IntVarP(&dnsThreadsFlag, "threads", "t", 30, "Eşzamanlı DNS sorgu limiti")

	RootCmd.AddCommand(dnsCmd)
}

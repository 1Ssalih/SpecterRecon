package cmd

import (
	"time"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

var (
	discoverTimeoutFlag float64
	discoverOutputFlag  string
)

var discoverCmd = &cobra.Command{
	Use:   "discover [target]",
	Short: "Sadece Host Keşfi (ARP/ICMP/TCP ping) çalıştırır",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		core.PrintBanner(version)
		verifyScopePermission(target)

		timeout := time.Duration(discoverTimeoutFlag * float64(time.Second))
		hosts, _ := modules.DiscoverHosts(target, nil, timeout, 50, discoverOutputFlag)
		core.PrintHostsTable(hosts)
	},
}

func init() {
	discoverCmd.Flags().Float64VarP(&discoverTimeoutFlag, "timeout", "t", 2.0, "Zaman aşımı süresi (saniye)")
	discoverCmd.Flags().StringVarP(&discoverOutputFlag, "output", "o", "output/hosts.json", "Çıktı JSON dosyası")

	RootCmd.AddCommand(discoverCmd)
}

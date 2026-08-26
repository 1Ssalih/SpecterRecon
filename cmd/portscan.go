package cmd

import (
	"time"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

var (
	psPortsFlag   string
	psThreadsFlag int
	psOutputFlag  string
)

var portscanCmd = &cobra.Command{
	Use:   "portscan [target]",
	Short: "Hedef üzerinde TCP Connect port taraması yapar",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		core.PrintBanner(version)
		verifyScopePermission(target)

		ports := modules.ParsePortSpecs(psPortsFlag)
		found, _ := modules.ScanTargetPorts(target, ports, psThreadsFlag, 1500*time.Millisecond, psOutputFlag)
		core.PrintPortsTable(found)
	},
}

func init() {
	portscanCmd.Flags().StringVarP(&psPortsFlag, "ports", "p", "top-100", "Taranacak portlar")
	portscanCmd.Flags().IntVarP(&psThreadsFlag, "threads", "t", 100, "Eşzamanlı bağlantı limiti")
	portscanCmd.Flags().StringVarP(&psOutputFlag, "output", "o", "output/ports.json", "Çıktı JSON dosyası")

	RootCmd.AddCommand(portscanCmd)
}

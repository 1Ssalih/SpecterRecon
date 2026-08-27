package cmd

import (
	"time"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

var (
	bannerInputFlag  string
	bannerOutputFlag string
)

var bannerCmd = &cobra.Command{
	Use:   "banner",
	Short: "Açık portlar için banner grabbing ve versiyon tespiti yapar",
	Example: `  specter-recon banner --authorized
  specter-recon banner -i output/ports.json -o output/services.json --authorized`,
	Run: func(cmd *cobra.Command, args []string) {
		core.PrintBanner(version)
		core.EnsureOutputDir("output")
		ports, err := core.LoadPorts(bannerInputFlag)
		if err != nil || len(ports) == 0 {
			core.LogError("Port listesi okunamadı veya boş: %s", bannerInputFlag)
			return
		}
		// Banner grabbing yetkili tarama gerektiriyor
		if len(ports) > 0 {
			verifyScopePermission(ports[0].IP)
		}

		services, _ := modules.GrabBannersAndServices(ports, 30, 3500*time.Millisecond, bannerOutputFlag)
		core.PrintServicesTable(services)
	},
}

func init() {
	bannerCmd.Flags().StringVarP(&bannerInputFlag, "input", "i", "output/ports.json", "Açık portlar JSON dosyası")
	bannerCmd.Flags().StringVarP(&bannerOutputFlag, "output", "o", "output/services.json", "Çıktı JSON dosyası")

	RootCmd.AddCommand(bannerCmd)
}

package cmd

import (
	"strings"
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
		core.EnsureOutputDir("output")
		var ports []core.PortInfo
		var err error

		if strings.HasSuffix(strings.ToLower(bannerInputFlag), ".xml") {
			_, impPorts, _, _, xmlErr := modules.LoadNmapXMLFile(bannerInputFlag)
			if xmlErr == nil && len(impPorts) > 0 {
				ports = impPorts
				core.LogSuccess("Nmap XML dosyasından %d açık port yüklendi.", len(ports))
			} else {
				err = xmlErr
			}
		} else {
			ports, err = core.LoadPorts(bannerInputFlag)
			if err != nil || len(ports) == 0 {
				// Try Masscan JSON parser
				_, mPorts, mErr := modules.LoadMasscanJSONFile(bannerInputFlag)
				if mErr == nil && len(mPorts) > 0 {
					ports, _ = modules.VerifyPortsWithHandshake(mPorts, 50, 1500*time.Millisecond)
					core.LogSuccess("Masscan JSON dosyasından %d açık port yüklendi ve teyit edildi.", len(ports))
					err = nil
				}
			}
		}

		if len(ports) == 0 {
			core.LogError("Port listesi okunamadı veya boş: %s (%v)", bannerInputFlag, err)
			return
		}
		// Banner grabbing yetkili tarama gerektiriyor
		if len(ports) > 0 {
			if !verifyScopePermission(ports[0].IP) {
				return
			}
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

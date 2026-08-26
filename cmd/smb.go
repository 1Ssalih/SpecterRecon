package cmd

import (
	"time"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

var smbCmd = &cobra.Command{
	Use:   "smb [target-ip]",
	Short: "Hedefte SMB/NetBIOS null session, SMBv1 ve SMB signing denetimi yapar",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		core.PrintBanner(version)
		verifyScopePermission(target)
		core.EnsureOutputDir("output")

		finding := modules.AuditSMBService(target, 445, 4*time.Second)
		core.PrintSmbTable([]core.SmbFinding{finding})
		_ = core.SaveSmbFindings([]core.SmbFinding{finding}, "output/smb_findings.json")
	},
}

func init() {
	RootCmd.AddCommand(smbCmd)
}

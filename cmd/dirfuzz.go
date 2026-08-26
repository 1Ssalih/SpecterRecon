package cmd

import (
	"path/filepath"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
)

var (
	dfWordlistFlag string
	dfThreadsFlag  int
	dfDelayFlag    int
	dfJSONFlag     string
	dfTxtFlag      string
)

var dirfuzzCmd = &cobra.Command{
	Use:   "dirfuzz [url]",
	Short: "Web hedefinde dizin/dosya fuzzing çalıştırır",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]
		core.PrintBanner(version)
		core.EnsureOutputDir("output")
		verifyScopePermission(url)

		words := modules.LoadWordlist(dfWordlistFlag)
		if len(words) == 0 {
			core.LogError("Wordlist boş veya bulunamadı: %s", dfWordlistFlag)
			return
		}

		matchTag := filepath.Base(dfWordlistFlag)
		findings := modules.FuzzTargetService(url, words, matchTag, dfThreadsFlag, dfDelayFlag)
		_ = core.SaveFindings(findings, dfJSONFlag, dfTxtFlag)
		core.PrintDirFindingsTable(findings)
		core.LogSuccess("Dizin taraması bitti: %d yol bulundu.", len(findings))
	},
}

func init() {
	dirfuzzCmd.Flags().StringVarP(&dfWordlistFlag, "wordlist", "w", "wordlists/common.txt", "Kullanılacak wordlist dosyası")
	dirfuzzCmd.Flags().IntVarP(&dfThreadsFlag, "threads", "t", 25, "Eşzamanlı bağlantı limiti")
	dirfuzzCmd.Flags().IntVarP(&dfDelayFlag, "delay", "d", 0, "İstekler arası gecikme (ms)")
	dirfuzzCmd.Flags().StringVar(&dfJSONFlag, "output-json", "output/dirs.json", "Çıktı JSON dosyası")
	dirfuzzCmd.Flags().StringVar(&dfTxtFlag, "output-txt", "output/findings.txt", "Çıktı metin dosyası")

	RootCmd.AddCommand(dirfuzzCmd)
}

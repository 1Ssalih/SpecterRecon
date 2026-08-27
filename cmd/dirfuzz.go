package cmd

import (
	"path/filepath"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"os"
)

var (
	dfWordlistFlag     string
	dfThreadsFlag      int
	dfDelayFlag        int
	dfJSONFlag         string
	dfTxtFlag          string
	dfServiceFlag      string // --service: jenkins, apache, wordpress vb.
	dfWordlistSizeFlag string // --wordlist-size: quick veya full
)

var dirfuzzCmd = &cobra.Command{
	Use:   "dirfuzz [url]",
	Short: "Web hedefinde dizin/dosya fuzzing çalıştırır (akıllı wordlist seçimi destekler)",
	Example: `  # Varsayılan wordlist ile
  specter-recon dirfuzz http://example.com --authorized

  # Servis bazlı akıllı wordlist seçimi
  specter-recon dirfuzz http://example.com --service jenkins --authorized

  # SecLists ile kapsamlı tarama
  specter-recon dirfuzz http://example.com --wordlist-size full --authorized

  # Özel wordlist ile
  specter-recon dirfuzz http://example.com -w my_wordlist.txt --authorized`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]
		core.PrintBanner(version)
		core.EnsureOutputDir("output")
		verifyScopePermission(url)

		selectedWordlist := dfWordlistFlag

		// Akıllı wordlist seçimi: --service verilmişse servise göre wordlist seç
		if dfServiceFlag != "" {
			wordlistMap := loadWordlistMap()
			if len(wordlistMap) > 0 {
				// Sahte bir ServiceDetail oluştur, akıllı eşleştirme için
				fakeSvc := core.ServiceDetail{
					ServiceName:        "http",
					ServiceDescription: dfServiceFlag,
				}
				wPath, key := modules.SelectWordlistForService(fakeSvc, wordlistMap, dfWordlistFlag)
				if key != "default" && key != "" {
					core.LogInfo("Servis '%s' için akıllı wordlist seçildi: %s (%s)", dfServiceFlag, filepath.Base(wPath), key)
					selectedWordlist = wPath
				}
			}
		}

		// --wordlist-size full ise SecLists'ten büyük listeyi kullan
		if dfWordlistSizeFlag == "full" && dfServiceFlag == "" {
			fullPath := "wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
			if _, err := os.Stat(fullPath); err == nil {
				selectedWordlist = fullPath
				core.LogInfo("SecLists kapsamlı wordlist kullanılıyor: %s", fullPath)
			} else {
				core.LogWarning("SecLists bulunamadı (%s), varsayılan küçük wordlist kullanılıyor.", fullPath)
			}
		}

		words := modules.LoadWordlist(selectedWordlist)
		if len(words) == 0 {
			core.LogError("Wordlist boş veya bulunamadı: %s", selectedWordlist)
			return
		}

		matchTag := filepath.Base(selectedWordlist)
		findings := modules.FuzzTargetService(url, words, matchTag, dfThreadsFlag, dfDelayFlag)
		_ = core.SaveFindings(findings, dfJSONFlag, dfTxtFlag)
		core.PrintDirFindingsTable(findings)
		core.LogSuccess("Dizin taraması bitti: %d yol bulundu.", len(findings))
	},
}

// loadWordlistMap reads service_wordlist_map.yaml for smart wordlist selection.
func loadWordlistMap() map[string]string {
	data, err := os.ReadFile("wordlists/service_wordlist_map.yaml")
	if err != nil {
		return nil
	}
	var m map[string]string
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}

func init() {
	dirfuzzCmd.Flags().StringVarP(&dfWordlistFlag, "wordlist", "w", "wordlists/common.txt", "Kullanılacak wordlist dosyası")
	dirfuzzCmd.Flags().IntVarP(&dfThreadsFlag, "threads", "t", 25, "Eşzamanlı bağlantı limiti")
	dirfuzzCmd.Flags().IntVarP(&dfDelayFlag, "delay", "d", 0, "İstekler arası gecikme (ms)")
	dirfuzzCmd.Flags().StringVar(&dfJSONFlag, "output-json", "output/dirs.json", "Çıktı JSON dosyası")
	dirfuzzCmd.Flags().StringVar(&dfTxtFlag, "output-txt", "output/findings.txt", "Çıktı metin dosyası")
	dirfuzzCmd.Flags().StringVar(&dfServiceFlag, "service", "", "Hedef servis tipi (jenkins, apache, wordpress vb.) — akıllı wordlist seçimi için")
	dirfuzzCmd.Flags().StringVar(&dfWordlistSizeFlag, "wordlist-size", "quick", "Wordlist boyutu: 'quick' (küçük yerleşik listeler) veya 'full' (SecLists)")

	RootCmd.AddCommand(dirfuzzCmd)
}

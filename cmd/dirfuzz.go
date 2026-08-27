package cmd

import (
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/specter-recon/recon-tool/core"
	"github.com/specter-recon/recon-tool/modules"
	"github.com/spf13/cobra"
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
	Example: `  # Varsayılan akıllı wordlist ile
  specter-recon dirfuzz http://example.com --authorized

  # Servis bazlı akıllı wordlist seçimi (iis, apache, jenkins, wordpress, tomcat vb.)
  specter-recon dirfuzz http://example.com --service iis --authorized

  # SecLists ile derin ve kapsamlı tarama
  specter-recon dirfuzz http://example.com --wordlist-size full --authorized

  # Özel wordlist ve thread limiti ile
  specter-recon dirfuzz http://example.com -w custom.txt -t 50 --authorized`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetURL := args[0]
		core.PrintBanner(version)
		core.EnsureOutputDir("output")
		if !verifyScopePermission(targetURL) {
			return
		}

		// Ensure URL has scheme
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			targetURL = "http://" + targetURL
		}

		wordlistMap := modules.LoadServiceWordlistMap("", dfWordlistSizeFlag)
		defaultWordlist := "wordlists/common.txt"
		if dfWordlistSizeFlag == "full" {
			defaultWordlist = "wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
		}
		if cmd.Flags().Changed("wordlist") {
			defaultWordlist = dfWordlistFlag
		}

		selectedWordlists := []string{defaultWordlist}
		matchTag := "common"

		if dfServiceFlag != "" {
			// Explicit service provided by user
			fakeSvc := core.ServiceDetail{
				ServiceName:        "http",
				ServiceDescription: dfServiceFlag,
			}
			selectedWordlists, matchTag = modules.SelectWordlistForService(fakeSvc, wordlistMap, defaultWordlist)
			var baseNames []string
			for _, p := range selectedWordlists {
				baseNames = append(baseNames, filepath.Base(p))
			}
			core.LogInfo("Belirtilen servis '%s' için wordlist: %s (Kategori: %s)", dfServiceFlag, strings.Join(baseNames, "+"), matchTag)
		} else if !cmd.Flags().Changed("wordlist") {
			// Auto-probe target URL to detect service banner
			core.LogInfo("Hedef teknoloji tespiti için hızlı HTTP probe yapılıyor...")
			u, err := url.Parse(targetURL)
			if err == nil {
				host := u.Hostname()
				port := 80
				isSSL := u.Scheme == "https"
				if isSSL {
					port = 443
				}
				if u.Port() != "" {
					if p, pErr := strconv.Atoi(u.Port()); pErr == nil {
						port = p
					}
				}
				probeRes := modules.ProbeHTTPService(host, port, isSSL, 3*time.Second)
				if probeRes.IsHTTP {
					fakeSvc := core.ServiceDetail{
						ServiceName:      "http",
						HTTPServer:       probeRes.Server,
						HTTPTitle:        probeRes.Title,
						HTTPTechnologies: probeRes.Technologies,
						DetectedTechs:    probeRes.DetectedTechs,
					}
					selectedWordlists, matchTag = modules.SelectWordlistForService(fakeSvc, wordlistMap, defaultWordlist)
					if matchTag != "default" && matchTag != "common" {
						var baseNames []string
						for _, p := range selectedWordlists {
							baseNames = append(baseNames, filepath.Base(p))
						}
						core.LogSuccess("Otomatik servis tespiti yapıldı (%s %s) ➔ Wordlist: %s (%s)", probeRes.Server, probeRes.Title, strings.Join(baseNames, "+"), matchTag)
					}
				}
			}
		}

		var wordlistsToMerge [][]string
		for _, path := range selectedWordlists {
			wordlistsToMerge = append(wordlistsToMerge, modules.LoadWordlist(path))
		}
		words := modules.MergeUnique(wordlistsToMerge...)
		if len(words) == 0 {
			core.LogError("Wordlist boş veya bulunamadı: %v", selectedWordlists)
			return
		}

		var displayNames []string
		for _, p := range selectedWordlists {
			displayNames = append(displayNames, filepath.Base(p))
		}
		core.LogInfo("Dizin taraması başlatılıyor (Liste: %s, Toplam %d kelime)...", strings.Join(displayNames, "+"), len(words))
		findings := modules.FuzzTargetService(targetURL, words, matchTag, dfThreadsFlag, dfDelayFlag)
		_ = core.SaveFindings(findings, dfJSONFlag, dfTxtFlag)
		core.PrintDirFindingsTable(findings)
		core.LogSuccess("Dizin taraması tamamlandı: %d yol bulundu (%s).", len(findings), dfTxtFlag)
	},
}

func init() {
	dirfuzzCmd.Flags().StringVarP(&dfWordlistFlag, "wordlist", "w", "wordlists/common.txt", "Kullanılacak wordlist dosyası")
	dirfuzzCmd.Flags().IntVarP(&dfThreadsFlag, "threads", "t", 25, "Eşzamanlı bağlantı limiti")
	dirfuzzCmd.Flags().IntVarP(&dfDelayFlag, "delay", "d", 0, "İstekler arası gecikme (ms)")
	dirfuzzCmd.Flags().StringVar(&dfJSONFlag, "output-json", "output/dirs.json", "Çıktı JSON dosyası")
	dirfuzzCmd.Flags().StringVar(&dfTxtFlag, "output-txt", "output/findings.txt", "Çıktı metin dosyası")
	dirfuzzCmd.Flags().StringVar(&dfServiceFlag, "service", "", "Hedef servis tipi (iis, apache, jenkins, wordpress, tomcat, php vb.)")
	dirfuzzCmd.Flags().StringVar(&dfWordlistSizeFlag, "wordlist-size", "quick", "Wordlist boyutu: 'quick' (hızlı/hafif) veya 'full' (SecLists)")

	RootCmd.AddCommand(dirfuzzCmd)
}

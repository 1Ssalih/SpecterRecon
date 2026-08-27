package cmd

import (
	"bufio"
	"os"
	"strings"
	"time"

	"github.com/pterm/pterm"
	"github.com/specter-recon/recon-tool/core"
	"github.com/spf13/cobra"
)

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "İnteraktif Konsol Modunu başlatır (her seferinde exe adı yazmanıza gerek kalmaz)",
	Example: `  # İnteraktif konsol moduna gir
  specter-recon shell`,
	Run: func(cmd *cobra.Command, args []string) {
		StartInteractiveShell(cmd.Root())
	},
}

func init() {
	RootCmd.AddCommand(shellCmd)
}

// StartInteractiveShell launches an interactive terminal session (like Metasploit console).
func StartInteractiveShell(rootCmd *cobra.Command) {
	isInteractiveSession = true
	core.PrintBanner(version)

	pterm.DefaultBox.
		WithTitle("⚡ SPECTER-RECON INTERACTIVE CONSOLE").
		WithTitleTopCenter().
		WithBoxStyle(pterm.NewStyle(pterm.FgCyan, pterm.Bold)).
		Println(
			pterm.FgWhite.Sprint("İnteraktif Konsol Modu Aktif (Metasploit Style).\n") +
				pterm.FgGray.Sprint("Doğrudan komutlarınızı yazabilirsiniz. 'exit' ile çıkabilir, 'help' ile kılavuzu görebilirsiniz.\n\n") +
				pterm.FgLightCyan.Sprint("Hızlı Başlangıç Komutları:\n") +
				pterm.FgCyan.Sprint("  • scan <hedef> --authorized               ") + pterm.FgGray.Sprint("➔ Temel Boru Hattı Taraması\n") +
				pterm.FgCyan.Sprint("  • fullscan <hedef> --authorized           ") + pterm.FgGray.Sprint("➔ Genişletilmiş Tam Denetim (SSL/HTTP/SSH)\n") +
				pterm.FgCyan.Sprint("  • scan <hedef> --wordlist-size full       ") + pterm.FgGray.Sprint("➔ SecLists Derin Web Dizin Fuzzing\n") +
				pterm.FgCyan.Sprint("  • ssl <host:443>                          ") + pterm.FgGray.Sprint("➔ SSL/TLS Sertifika Audit\n") +
				pterm.FgCyan.Sprint("  • dirfuzz <url> --service iis             ") + pterm.FgGray.Sprint("➔ Servise Özel Akıllı Fuzzing\n") +
				pterm.FgCyan.Sprint("  • report -t \"Hedef Adı\"                 ") + pterm.FgGray.Sprint("➔ HTML Dashboard & Summary Üret"),
		)

	scanner := bufio.NewScanner(os.Stdin)
	for {
		pterm.Print(pterm.NewStyle(pterm.FgLightCyan, pterm.Bold).Sprintf("\nspecter-recon > "))
		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if line == "exit" || line == "quit" || line == "q" {
			pterm.Println(pterm.FgYellow.Sprint("İnteraktif konsoldan çıkılıyor. İyi çalışmalar!"))
			break
		}

		if line == "clear" || line == "cls" {
			print("\033[H\033[2J")
			continue
		}

		// Split command line into args
		cmdArgs := parseCommandLine(line)
		if len(cmdArgs) == 0 {
			continue
		}

		// Smart prefix stripping: If user accidentally types ".\specter-recon.exe scan ..." or "specter-recon scan ..."
		firstArg := strings.ToLower(cmdArgs[0])
		if strings.HasSuffix(firstArg, "specter-recon.exe") || strings.HasSuffix(firstArg, "specter-recon") {
			cmdArgs = cmdArgs[1:]
			if len(cmdArgs) == 0 {
				continue
			}
		}

		// Reset authorizedFlag before command execution unless --authorized in args
		hasAuthArg := false
		for _, a := range cmdArgs {
			if a == "--authorized" {
				hasAuthArg = true
				break
			}
		}
		authorizedFlag = hasAuthArg

		// Execute root command with parsed args
		startTime := time.Now()
		rootCmd.SetArgs(cmdArgs)
		_ = rootCmd.Execute()

		// Print subtle elapsed time if it was a real command
		elapsed := time.Since(startTime).Seconds()
		if elapsed >= 0.5 {
			core.LogInfo("Oturum Komutu Tamamlandı (%s) | Toplam Süre: %.2fs", cmdArgs[0], elapsed)
		}
	}
}

// parseCommandLine splits a string into command arguments, respecting quotes.
func parseCommandLine(cmdLine string) []string {
	var args []string
	var current strings.Builder
	inQuotes := false
	quoteChar := rune(0)

	for _, ch := range cmdLine {
		switch {
		case ch == '"' || ch == '\'':
			if inQuotes && ch == quoteChar {
				inQuotes = false
			} else if !inQuotes {
				inQuotes = true
				quoteChar = ch
			} else {
				current.WriteRune(ch)
			}
		case ch == ' ' && !inQuotes:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(ch)
		}
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

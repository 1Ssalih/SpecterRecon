package cmd

import (
	"bufio"
	"os"
	"strings"

	"github.com/pterm/pterm"
	"github.com/specter-recon/recon-tool/core"
	"github.com/spf13/cobra"
)

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "İnteraktif Konsol Modunu başlatır (her seferinde exe adı yazmanıza gerek kalmaz)",
	Run: func(cmd *cobra.Command, args []string) {
		StartInteractiveShell(cmd.Root())
	},
}

func init() {
	RootCmd.AddCommand(shellCmd)
}

// StartInteractiveShell launches an interactive terminal session (like Metasploit console).
func StartInteractiveShell(rootCmd *cobra.Command) {
	core.PrintBanner(version)
	pterm.DefaultBox.WithTitle("⚡ SPECTER-RECON İNTERAKTİF KONSOL MODU").
		WithBoxStyle(pterm.NewStyle(pterm.FgCyan, pterm.Bold)).
		Println("Her seferinde '.\\specter-recon.exe' yazmanıza gerek yok!\nDoğrudan komutlarınızı yazabilirsiniz.\nÖrnekler:\n  - fullscan scanme.nmap.org\n  - scan scanme.nmap.org --profile web\n  - ssl scanme.nmap.org:443\n  - smb 192.168.1.10\n  - creds 192.168.1.10\n  - dirfuzz http://scanme.nmap.org\n  - help\n  - exit")

	// In interactive shell mode, user is authorized
	authorizedFlag = true

	scanner := bufio.NewScanner(os.Stdin)
	for {
		pterm.Print(pterm.FgCyan.Sprintf("\nspecter-recon > "))
		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if line == "exit" || line == "quit" || line == "q" {
			pterm.Println(pterm.FgYellow.Sprint("İnteraktif konsoldan çıkılıyor. Görüşmek üzere!"))
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

		// Execute root command with parsed args
		rootCmd.SetArgs(cmdArgs)
		_ = rootCmd.Execute()
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

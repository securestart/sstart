package cli

import (
	_ "github.com/dirathea/sstart/internal/provider/aws"
	_ "github.com/dirathea/sstart/internal/provider/dotenv"
	_ "github.com/dirathea/sstart/internal/provider/gcsm"
	_ "github.com/dirathea/sstart/internal/provider/vault"
	"github.com/spf13/cobra"
)

var (
	configPath string
	verbose    bool
	providers  []string
)

var rootCmd = &cobra.Command{
	Use:   "sstart",
	Short: "Secure secrets management for subprocess execution",
	Long: `sstart is a CLI tool that fetches secrets from various providers,
combines them, and securely injects them into subprocesses.

Similar to tini but with automatic secret injection from multiple sources.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", ".sstart.yml", "Path to configuration file")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

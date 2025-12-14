package cli

import (
	"context"
	"fmt"

	_ "github.com/dirathea/sstart/internal/provider/aws"
	_ "github.com/dirathea/sstart/internal/provider/bitwarden"
	_ "github.com/dirathea/sstart/internal/provider/doppler"
	_ "github.com/dirathea/sstart/internal/provider/dotenv"
	_ "github.com/dirathea/sstart/internal/provider/gcsm"
	_ "github.com/dirathea/sstart/internal/provider/infisical"
	_ "github.com/dirathea/sstart/internal/provider/onepassword"
	_ "github.com/dirathea/sstart/internal/provider/vault"
	"github.com/dirathea/sstart/internal/app"
	"github.com/dirathea/sstart/internal/config"
	"github.com/dirathea/sstart/internal/secrets"
	"github.com/spf13/cobra"
)

var (
	configPath string
	verbose    bool
	providers  []string
)

var rootCmd = &cobra.Command{
	Use:   "sstart [flags] [-- <command> [args...]]",
	Short: "Secure secrets management for subprocess execution",
	Long: `sstart is a CLI tool that fetches secrets from various providers,
combines them, and securely injects them into subprocesses.

Similar to tini but with automatic secret injection from multiple sources.

Examples:
  sstart -- node index.js
  sstart --providers aws-prod,dotenv-dev -- node index.js
  sstart run -- node index.js  # backward compatible`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// If no arguments provided, show help
		if len(args) == 0 {
			return cmd.Help()
		}

		// Execute command with secrets injection
		ctx := context.Background()

		// Load configuration
		cfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Create collector and runner
		collector := secrets.NewCollector(cfg)
		runner := app.NewRunner(collector, cfg.Inherit)

		// Run the command
		return runner.Run(ctx, providers, args)
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", ".sstart.yml", "Path to configuration file")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringSliceVar(&providers, "providers", []string{}, "Comma-separated list of provider IDs to use (default: all providers)")
}

package cli

import (
	"context"
	"fmt"

	"github.com/dirathea/sstart/internal/app"
	"github.com/dirathea/sstart/internal/config"
	"github.com/dirathea/sstart/internal/secrets"
	"github.com/spf13/cobra"
)

var (
	runProviders []string
)

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command> [args...]",
	Short: "Run a command with injected secrets",
	Long: `Run a command with secrets automatically injected from configured providers.

Example:
  sstart run -- node index.js
  sstart run --providers aws-prod,dotenv-dev -- node index.js`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		// Load configuration
		cfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Create collector and runner
		collector := secrets.NewCollector(cfg, secrets.WithForceAuth(forceAuth))
		runner := app.NewRunner(collector, cfg.Inherit)

		// Run the command
		return runner.Run(ctx, runProviders, args)
	},
}

func init() {
	runCmd.Flags().StringSliceVar(&runProviders, "providers", []string{}, "Comma-separated list of provider IDs to use (default: all providers)")
	rootCmd.AddCommand(runCmd)
}

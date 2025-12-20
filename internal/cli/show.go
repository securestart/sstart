package cli

import (
	"context"
	"fmt"

	"github.com/dirathea/sstart/internal/config"
	"github.com/dirathea/sstart/internal/secrets"
	"github.com/spf13/cobra"
)

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show collected secrets (masked)",
	Long: `Display all secrets that would be injected, with values masked for security.
Only the first 2 and last 2 characters are shown.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		// Load configuration
		cfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Collect secrets
		collector := secrets.NewCollector(cfg, secrets.WithForceAuth(forceAuth))
		showProviders := providers
		if len(showProviders) == 0 {
			showProviders = nil // Use all providers
		}
		envSecrets, err := collector.Collect(ctx, showProviders)
		if err != nil {
			return fmt.Errorf("failed to collect secrets: %w", err)
		}

		// Display secrets (masked)
		for key, value := range envSecrets {
			masked := secrets.Mask(value)
			fmt.Printf("%s=%s\n", key, masked)
		}

		return nil
	},
}

func init() {
	showCmd.Flags().StringSliceVar(&providers, "providers", []string{}, "Comma-separated list of provider IDs to use (default: all providers)")
	rootCmd.AddCommand(showCmd)
}

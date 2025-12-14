package cli

import (
	"github.com/spf13/cobra"
)

var shCmd = &cobra.Command{
	Use:   "sh",
	Short: "Generate shell commands to export secrets",
	Long: `Generate shell commands to export secrets. Useful for sourcing in shell scripts.

Example:
  eval "$(sstart sh)"
  source <(sstart sh)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// This is a convenience wrapper around 'env' command
		// Redirect to env command with shell format
		oldFormat := envFormat
		envFormat = "shell"
		err := envCmd.RunE(cmd, args)
		envFormat = oldFormat
		return err
	},
}

func init() {
	rootCmd.AddCommand(shCmd)
}

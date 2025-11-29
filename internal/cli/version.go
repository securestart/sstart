package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version   = "dev"
	commit    = "unknown"
	date      = "unknown"
	buildInfo = ""
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  "Print version information including build details",
	Run: func(cmd *cobra.Command, args []string) {
		versionStr := version
		if versionStr != "dev" && versionStr != "" && versionStr[0] != 'v' {
			versionStr = "v" + versionStr
		}
		fmt.Printf("sstart version %s", versionStr)
		if commit != "unknown" {
			fmt.Printf(" (commit: %s", commit)
			if date != "unknown" {
				fmt.Printf(", built: %s", date)
			}
			fmt.Print(")")
		}
		if buildInfo != "" {
			fmt.Printf("\n%s", buildInfo)
		}
		fmt.Println()
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

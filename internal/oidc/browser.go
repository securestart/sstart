package oidc

import (
	"os/exec"
	"runtime"
)

// openBrowser attempts to open the given URL in the default browser
func openBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		// Try xdg-open first, then fallback to other common browsers
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		// For unsupported platforms, try xdg-open as a fallback
		cmd = exec.Command("xdg-open", url)
	}

	return cmd.Start()
}


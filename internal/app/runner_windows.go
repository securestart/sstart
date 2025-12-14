//go:build windows

package app

import (
	"os"
	"os/exec"
	"os/signal"
)

// setProcessGroup is a no-op on Windows (process groups not supported)
func setProcessGroup(cmd *exec.Cmd) {
	// No-op on Windows
}

// registerSignals registers signals for Windows systems
func registerSignals(sigChan chan os.Signal) {
	// On Windows, only os.Interrupt (Ctrl+C) is available
	signal.Notify(sigChan, os.Interrupt)
}

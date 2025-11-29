//go:build !windows

package app

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// setProcessGroup sets up the process group for Unix systems
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
}

// registerSignals registers signals for Unix systems
func registerSignals(sigChan chan os.Signal) {
	// Register for interrupt and terminate signals
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
}


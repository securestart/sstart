package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"

	"github.com/dirathea/sstart/internal/secrets"
)

// Runner executes subprocesses with injected secrets
type Runner struct {
	collector *secrets.Collector
	resetEnv  bool
}

// NewRunner creates a new runner instance
func NewRunner(collector *secrets.Collector, resetEnv bool) *Runner {
	return &Runner{
		collector: collector,
		resetEnv:  resetEnv,
	}
}

// Run executes a command with injected secrets
func (r *Runner) Run(ctx context.Context, providerIDs []string, command []string) error {
	// Collect secrets
	envSecrets, err := r.collector.Collect(ctx, providerIDs)
	if err != nil {
		return fmt.Errorf("failed to collect secrets: %w", err)
	}

	// Prepare environment
	env := os.Environ()
	if r.resetEnv {
		env = make([]string, 0)
	}

	// Merge secrets into environment
	for key, value := range envSecrets {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Prepare command
	if len(command) == 0 {
		return fmt.Errorf("no command specified")
	}

	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Set up process group so subprocess runs in its own process group (Unix only)
	setProcessGroup(cmd)

	// Start the command
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	// Set up signal forwarding for kill signals only (cross-platform compatible)
	sigChan := make(chan os.Signal, 1)
	// Only register for interrupt and terminate signals to ensure Windows compatibility
	registerSignals(sigChan)

	// Goroutine to forward signals to subprocess
	go func() {
		for sig := range sigChan {
			if cmd.Process != nil {
				// Forward the signal directly to the subprocess (cross-platform)
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	// Wait for command to complete
	waitErr := cmd.Wait()

	// Stop forwarding signals
	signal.Stop(sigChan)
	close(sigChan)

	if waitErr != nil {
		// Get exit code if available (cross-platform compatible)
		if exitError, ok := waitErr.(*exec.ExitError); ok {
			// ExitCode() method is available on all platforms (Go 1.12+)
			os.Exit(exitError.ExitCode())
			return nil
		}
		return waitErr
	}

	return nil
}

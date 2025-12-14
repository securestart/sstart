package end2end

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// getProjectRoot finds the project root directory by looking for go.mod
func getProjectRoot(t *testing.T) string {
	t.Helper()
	// When go test runs, it typically runs from the project root
	// Walk up the directory tree to find go.mod
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root directory
			t.Fatalf("Could not find go.mod in any parent directory")
		}
		dir = parent
	}
}

// TestE2E_RunCommand tests the run command with secret injection and inherit config
func TestE2E_RunCommand(t *testing.T) {
	ctx := context.Background()

	// Setup containers
	localstack, vaultContainer := SetupContainers(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
		if err := vaultContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate vault container: %v", err)
		}
	}()

	// Set up AWS secret
	secretName := "test/run/secrets"
	secretData := map[string]string{
		"RUN_API_KEY":     "run-secret-api-key-12345",
		"RUN_DB_PASSWORD": "run-secret-db-password",
	}
	SetupAWSSecret(ctx, t, localstack, secretName, secretData)

	// Set up Vault secret
	vaultPath := "run/config"
	SetupVaultSecret(ctx, t, vaultContainer, vaultPath, map[string]interface{}{
		"RUN_VAULT_KEY": "run-vault-secret-value",
	})

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	// Test with inherit: true (default behavior - should inherit system env)
	t.Run("inherit_true", func(t *testing.T) {
		configYAML := fmt.Sprintf(`
inherit: true
providers:
  - kind: aws_secretsmanager
    id: aws-run
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      RUN_API_KEY: RUN_API_KEY
      RUN_DB_PASSWORD: RUN_DB_PASSWORD
  
  - kind: vault
    id: vault-run
    path: %s
    address: %s
    token: test-token
    mount: secret
    keys:
      RUN_VAULT_KEY: RUN_VAULT_KEY
`, secretName, localstack.Endpoint, vaultPath, vaultContainer.Address)

		if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
			t.Fatalf("Failed to write config file: %v", err)
		}

		// Set a system environment variable to test inheritance
		os.Setenv("SYSTEM_ENV_VAR", "system-value-123")
		defer os.Unsetenv("SYSTEM_ENV_VAR")

		// Create a test script that checks for secrets and system env
		testScript := filepath.Join(tmpDir, "test_script.sh")
		scriptContent := `#!/bin/sh
# Check if secrets are accessible
if [ "$RUN_API_KEY" != "run-secret-api-key-12345" ]; then
  echo "ERROR: RUN_API_KEY mismatch. Got: $RUN_API_KEY"
  exit 1
fi

if [ "$RUN_DB_PASSWORD" != "run-secret-db-password" ]; then
  echo "ERROR: RUN_DB_PASSWORD mismatch. Got: $RUN_DB_PASSWORD"
  exit 1
fi

if [ "$RUN_VAULT_KEY" != "run-vault-secret-value" ]; then
  echo "ERROR: RUN_VAULT_KEY mismatch. Got: $RUN_VAULT_KEY"
  exit 1
fi

# Check if system env var is inherited (should be when inherit=true)
if [ "$SYSTEM_ENV_VAR" != "system-value-123" ]; then
  echo "ERROR: SYSTEM_ENV_VAR not inherited. Got: $SYSTEM_ENV_VAR"
  exit 1
fi

echo "SUCCESS: All secrets accessible and system env inherited"
exit 0
`
		if err := os.WriteFile(testScript, []byte(scriptContent), 0755); err != nil {
			t.Fatalf("Failed to write test script: %v", err)
		}

		// Build sstart binary
		sstartBinary := filepath.Join(tmpDir, "sstart")
		projectRoot := getProjectRoot(t)
		cmdPath := filepath.Join(projectRoot, "cmd", "sstart")
		buildCmd := exec.CommandContext(ctx, "go", "build", "-o", sstartBinary, cmdPath)
		buildCmd.Dir = projectRoot
		if err := buildCmd.Run(); err != nil {
			t.Fatalf("Failed to build sstart binary: %v", err)
		}

		// Run sstart with the test script
		runCmd := exec.CommandContext(ctx, sstartBinary, "--config", configFile, "run", "--", testScript)
		runCmd.Dir = tmpDir
		output, err := runCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to run sstart command: %v\nOutput: %s", err, output)
		}

		if !strings.Contains(string(output), "SUCCESS") {
			t.Errorf("Test script failed. Output: %s", output)
		}
	})

	// Test with inherit: false (should NOT inherit system env, only secrets)
	t.Run("inherit_false", func(t *testing.T) {
		configYAML := fmt.Sprintf(`
inherit: false
providers:
  - kind: aws_secretsmanager
    id: aws-run
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      RUN_API_KEY: RUN_API_KEY
      RUN_DB_PASSWORD: RUN_DB_PASSWORD
  
  - kind: vault
    id: vault-run
    path: %s
    address: %s
    token: test-token
    mount: secret
    keys:
      RUN_VAULT_KEY: RUN_VAULT_KEY
`, secretName, localstack.Endpoint, vaultPath, vaultContainer.Address)

		if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
			t.Fatalf("Failed to write config file: %v", err)
		}

		// Set a system environment variable to test that it's NOT inherited
		os.Setenv("SYSTEM_ENV_VAR", "system-value-123")
		defer os.Unsetenv("SYSTEM_ENV_VAR")

		// Create a test script that checks for secrets and verifies system env is NOT inherited
		testScript := filepath.Join(tmpDir, "test_script_no_inherit.sh")
		scriptContent := `#!/bin/sh
# Check if secrets are accessible
if [ "$RUN_API_KEY" != "run-secret-api-key-12345" ]; then
  echo "ERROR: RUN_API_KEY mismatch. Got: $RUN_API_KEY"
  exit 1
fi

if [ "$RUN_DB_PASSWORD" != "run-secret-db-password" ]; then
  echo "ERROR: RUN_DB_PASSWORD mismatch. Got: $RUN_DB_PASSWORD"
  exit 1
fi

if [ "$RUN_VAULT_KEY" != "run-vault-secret-value" ]; then
  echo "ERROR: RUN_VAULT_KEY mismatch. Got: $RUN_VAULT_KEY"
  exit 1
fi

# Check if system env var is NOT inherited (should be empty when inherit=false)
if [ -n "$SYSTEM_ENV_VAR" ]; then
  echo "ERROR: SYSTEM_ENV_VAR should not be inherited but got: $SYSTEM_ENV_VAR"
  exit 1
fi

echo "SUCCESS: All secrets accessible and system env NOT inherited"
exit 0
`
		if err := os.WriteFile(testScript, []byte(scriptContent), 0755); err != nil {
			t.Fatalf("Failed to write test script: %v", err)
		}

		// Build sstart binary (reuse if already built)
		sstartBinary := filepath.Join(tmpDir, "sstart")
		if _, err := os.Stat(sstartBinary); os.IsNotExist(err) {
			projectRoot := getProjectRoot(t)
			cmdPath := filepath.Join(projectRoot, "cmd", "sstart")
			buildCmd := exec.CommandContext(ctx, "go", "build", "-o", sstartBinary, cmdPath)
			buildCmd.Dir = projectRoot
			if err := buildCmd.Run(); err != nil {
				t.Fatalf("Failed to build sstart binary: %v", err)
			}
		}

		// Run sstart with the test script
		runCmd := exec.CommandContext(ctx, sstartBinary, "--config", configFile, "run", "--", testScript)
		runCmd.Dir = tmpDir
		output, err := runCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to run sstart command: %v\nOutput: %s", err, output)
		}

		if !strings.Contains(string(output), "SUCCESS") {
			t.Errorf("Test script failed. Output: %s", output)
		}
	})

	t.Logf("Successfully tested run command with secret injection and inherit config")
}

// TestE2E_RunCommand_SignalHandling tests that signals are properly forwarded to the subprocess
func TestE2E_RunCommand_SignalHandling(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)

	// Set up AWS secret (minimal setup for signal test)
	secretName := "test/signal/secrets"
	secretData := map[string]string{
		"SIGNAL_TEST_KEY": "signal-test-value",
	}
	SetupAWSSecret(ctx, t, localstack, secretName, secretData)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
inherit: true
providers:
  - kind: aws_secretsmanager
    id: aws-signal
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      SIGNAL_TEST_KEY: SIGNAL_TEST_KEY
`, secretName, localstack.Endpoint)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create a test script that runs indefinitely and handles signals
	signalReceivedFile := filepath.Join(tmpDir, "signal_received.txt")
	// Use absolute path to ensure the script can write to the file regardless of working directory
	absSignalFile, err := filepath.Abs(signalReceivedFile)
	if err != nil {
		t.Fatalf("Failed to get absolute path for signal file: %v", err)
	}
	testScript := filepath.Join(tmpDir, "signal_test_script.sh")
	scriptContent := fmt.Sprintf(`#!/bin/sh
# Trap SIGTERM and SIGINT to write to file and exit
trap 'echo "SIGNAL_RECEIVED" > %s; exit 0' TERM INT

# Verify secret is accessible
if [ "$SIGNAL_TEST_KEY" != "signal-test-value" ]; then
  echo "ERROR: SIGNAL_TEST_KEY not accessible"
  exit 1
fi

# Run indefinitely until signal is received
while true; do
  sleep 1
done
`, absSignalFile)

	if err := os.WriteFile(testScript, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("Failed to write test script: %v", err)
	}

	// Build sstart binary
	sstartBinary := filepath.Join(tmpDir, "sstart")
	projectRoot := getProjectRoot(t)
	cmdPath := filepath.Join(projectRoot, "cmd", "sstart")
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", sstartBinary, cmdPath)
	buildCmd.Dir = projectRoot
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build sstart binary: %v", err)
	}

	// Start sstart with the test script
	runCmd := exec.CommandContext(ctx, sstartBinary, "--config", configFile, "run", "--", testScript)
	runCmd.Dir = tmpDir
	runCmd.Stdout = os.Stdout
	runCmd.Stderr = os.Stderr

	if err := runCmd.Start(); err != nil {
		t.Fatalf("Failed to start sstart command: %v", err)
	}

	// Give the subprocess time to start and the signal handler to be set up
	time.Sleep(1 * time.Second)

	// Verify the subprocess is running
	if runCmd.Process == nil {
		t.Fatalf("Process not started")
	}

	// Verify the subprocess script is actually running by checking if the process is still alive
	// This ensures the subprocess has fully started before we send the signal
	if err := runCmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("Process is not running: %v", err)
	}

	// Send SIGTERM to the sstart process
	// This should be forwarded to the subprocess
	if err := runCmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("Failed to send SIGTERM: %v", err)
	}

	// Wait for the process to exit (with timeout)
	done := make(chan error, 1)
	go func() {
		done <- runCmd.Wait()
	}()

	select {
	case err := <-done:
		// Process exited
		if err != nil {
			// Check if it's an exit error (which is expected)
			if _, ok := err.(*exec.ExitError); !ok {
				t.Errorf("Process exited with unexpected error: %v", err)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Process did not exit within 5 seconds after signal")
	}

	// Verify the signal was received by the subprocess
	// Give it a moment to write the file
	time.Sleep(500 * time.Millisecond)

	if _, err := os.Stat(absSignalFile); os.IsNotExist(err) {
		t.Fatalf("Signal was not received by subprocess - file %s was not created", absSignalFile)
	}

	content, err := os.ReadFile(absSignalFile)
	if err != nil {
		t.Fatalf("Failed to read signal received file: %v", err)
	}

	if !strings.Contains(string(content), "SIGNAL_RECEIVED") {
		t.Errorf("Signal was not properly handled. File content: %s", string(content))
	}

	t.Logf("Successfully tested signal handling - signal was forwarded to subprocess")
}

// TestE2E_RunCommand_ExitCode tests that subprocess exit codes are properly propagated
func TestE2E_RunCommand_ExitCode(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)

	// Set up AWS secret (minimal setup for exit code test)
	secretName := "test/exitcode/secrets"
	secretData := map[string]string{
		"EXITCODE_TEST_KEY": "exitcode-test-value",
	}
	SetupAWSSecret(ctx, t, localstack, secretName, secretData)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
inherit: true
providers:
  - kind: aws_secretsmanager
    id: aws-exitcode
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      EXITCODE_TEST_KEY: EXITCODE_TEST_KEY
`, secretName, localstack.Endpoint)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Build sstart binary
	sstartBinary := filepath.Join(tmpDir, "sstart")
	projectRoot := getProjectRoot(t)
	cmdPath := filepath.Join(projectRoot, "cmd", "sstart")
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", sstartBinary, cmdPath)
	buildCmd.Dir = projectRoot
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build sstart binary: %v", err)
	}

	// Test cases: exit code -> expected exit code
	testCases := []struct {
		name         string
		exitCode     int
		expectedExit int
		description  string
	}{
		{
			name:         "exit_code_0",
			exitCode:     0,
			expectedExit: 0,
			description:  "Subprocess exits with code 0 (success)",
		},
		{
			name:         "exit_code_1",
			exitCode:     1,
			expectedExit: 1,
			description:  "Subprocess exits with code 1 (common error)",
		},
		{
			name:         "exit_code_42",
			exitCode:     42,
			expectedExit: 42,
			description:  "Subprocess exits with code 42 (arbitrary non-zero)",
		},
		{
			name:         "exit_code_127",
			exitCode:     127,
			expectedExit: 127,
			description:  "Subprocess exits with code 127 (command not found)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test script that exits with the specified code
			testScript := filepath.Join(tmpDir, fmt.Sprintf("exitcode_test_%d.sh", tc.exitCode))
			scriptContent := fmt.Sprintf(`#!/bin/sh
# Verify secret is accessible
if [ "$EXITCODE_TEST_KEY" != "exitcode-test-value" ]; then
  echo "ERROR: EXITCODE_TEST_KEY not accessible"
  exit 1
fi

# Exit with the specified code
exit %d
`, tc.exitCode)

			if err := os.WriteFile(testScript, []byte(scriptContent), 0755); err != nil {
				t.Fatalf("Failed to write test script: %v", err)
			}

			// Run sstart with the test script
			runCmd := exec.CommandContext(ctx, sstartBinary, "--config", configFile, "run", "--", testScript)
			runCmd.Dir = tmpDir

			err := runCmd.Run()

			// Check the exit code
			if err != nil {
				if exitError, ok := err.(*exec.ExitError); ok {
					actualExitCode := exitError.ExitCode()
					if actualExitCode != tc.expectedExit {
						t.Errorf("%s: Expected exit code %d, got %d", tc.description, tc.expectedExit, actualExitCode)
					} else {
						t.Logf("%s: Correctly propagated exit code %d", tc.description, actualExitCode)
					}
				} else {
					t.Errorf("%s: Process exited with non-ExitError: %v", tc.description, err)
				}
			} else {
				// No error means exit code 0
				if tc.expectedExit != 0 {
					t.Errorf("%s: Expected exit code %d, but process exited with code 0", tc.description, tc.expectedExit)
				} else {
					t.Logf("%s: Correctly propagated exit code 0", tc.description)
				}
			}
		})
	}

	t.Logf("Successfully tested exit code propagation")
}

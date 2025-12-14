package end2end

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dirathea/sstart/internal/config"
	_ "github.com/dirathea/sstart/internal/provider/doppler"
	"github.com/dirathea/sstart/internal/secrets"
)

// Tests for Doppler provider
// These tests require:
// 1. DOPPLER_TOKEN environment variable set (service token with read/write access)
// 2. SSTART_E2E_DOPPLER_PROJECT environment variable set (project name)
// 3. SSTART_E2E_DOPPLER_CONFIG environment variable set (config/environment name, e.g., "dev", "test")
// 4. Test secrets will be created and cleaned up automatically

// TestE2E_Doppler_WithKeys tests the Doppler provider with key mappings
func TestE2E_Doppler_WithKeys(t *testing.T) {
	ctx := context.Background()

	// Setup Doppler client
	client := SetupDopplerClient(ctx, t)

	// Get test project and config from environment variables
	project := GetDopplerTestProject(t)
	dopplerConfig := GetDopplerTestConfig(t)

	// Test secrets
	secretKey1 := "DOPPLER_API_KEY"
	secretValue1 := "doppler-secret-api-key-12345"
	secretKey2 := "DOPPLER_DB_PASSWORD"
	secretValue2 := "doppler-secret-db-password"
	secretKey3 := "DOPPLER_SECRET_VALUE"
	secretValue3 := "doppler-config-value"

	// Setup test secrets using batch create
	testSecrets := map[string]string{
		secretKey1: secretValue1,
		secretKey2: secretValue2,
		secretKey3: secretValue3,
	}
	SetupDopplerSecretsBatch(ctx, t, client, project, dopplerConfig, testSecrets)

	// Cleanup: delete test secrets after test completes using batch delete
	defer DeleteDopplerSecretsBatch(ctx, t, client, project, dopplerConfig, []string{secretKey1, secretKey2, secretKey3})

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: doppler
    id: doppler-test
    project: %s
    config: %s
    keys:
      %s: %s
      %s: %s
      %s: ==
`, project, dopplerConfig, secretKey1, secretKey1, secretKey2, secretKey2, secretKey3)

	if err := os.WriteFile(configFile, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load config
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Create collector
	collector := secrets.NewCollector(cfg)

	// Collect secrets from Doppler provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify Doppler secrets
	expectedSecrets := map[string]string{
		secretKey1: secretValue1,
		secretKey2: secretValue2,
		secretKey3: secretValue3, // Same name (==)
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from Doppler not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from Doppler: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from Doppler provider", len(collectedSecrets))
}

// TestE2E_Doppler_NoKeys tests the Doppler provider without key mappings
func TestE2E_Doppler_NoKeys(t *testing.T) {
	ctx := context.Background()

	// Setup Doppler client
	client := SetupDopplerClient(ctx, t)

	// Get test project and config from environment variables
	project := GetDopplerTestProject(t)
	dopplerConfig := GetDopplerTestConfig(t)

	// Test secrets
	secretKey1 := "DOPPLER_API_KEY"
	secretValue1 := "doppler-secret-api-key-67890"
	secretKey2 := "DOPPLER_DB_PASSWORD"
	secretValue2 := "doppler-secret-db-password"
	secretKey3 := "DOPPLER_SECRET_VALUE"
	secretValue3 := "doppler-config-value"

	// Setup test secrets using batch create
	testSecrets := map[string]string{
		secretKey1: secretValue1,
		secretKey2: secretValue2,
		secretKey3: secretValue3,
	}
	SetupDopplerSecretsBatch(ctx, t, client, project, dopplerConfig, testSecrets)

	// Cleanup: delete test secrets after test completes using batch delete
	defer DeleteDopplerSecretsBatch(ctx, t, client, project, dopplerConfig, []string{secretKey1, secretKey2, secretKey3})

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: doppler
    id: doppler-test
    project: %s
    config: %s
`, project, dopplerConfig)

	if err := os.WriteFile(configFile, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load config
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Create collector
	collector := secrets.NewCollector(cfg)

	// Collect secrets from Doppler provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify Doppler secrets (should use original key names)
	expectedSecrets := map[string]string{
		secretKey1: secretValue1,
		secretKey2: secretValue2,
		secretKey3: secretValue3,
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from Doppler not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from Doppler: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from Doppler provider without key mappings", len(collectedSecrets))
}

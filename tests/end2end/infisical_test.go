package end2end

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dirathea/sstart/internal/config"
	_ "github.com/dirathea/sstart/internal/provider/infisical"
	"github.com/dirathea/sstart/internal/secrets"
)

// Tests for Infisical provider
// These tests require:
// 1. INFISICAL_UNIVERSAL_AUTH_CLIENT_ID environment variable set
// 2. INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET environment variable set
// 3. SSTART_E2E_INFISICAL_PROJECT_ID environment variable set
// 4. SSTART_E2E_INFISICAL_ENVIRONMENT environment variable set
// 5. Test secrets must be pre-created in the Infisical project at the root path (/)

// TestE2E_Infisical_WithKeys tests the Infisical provider with key mappings
func TestE2E_Infisical_WithKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires real Infisical service")
	}
	ctx := context.Background()

	// Setup Infisical client
	client := SetupInfisicalClient(ctx, t)

	// Get test project ID and environment from environment variables
	projectID := GetInfisicalTestProjectID(t)
	environment := GetInfisicalTestEnvironment(t)

	// Test path and secrets
	secretPath := "/"
	secretKey1 := "INFISICAL_API_KEY"
	secretValue1 := "infisical-secret-api-key-12345"
	secretKey2 := "INFISICAL_DB_PASSWORD"
	secretValue2 := "infisical-secret-db-password"
	secretKey3 := "INFISICAL_CONFIG"
	secretValue3 := "infisical-config-value"

	// Setup test secrets using batch create
	testSecrets := map[string]string{
		secretKey1: secretValue1,
		secretKey2: secretValue2,
		secretKey3: secretValue3,
	}
	SetupInfisicalSecretsBatch(ctx, t, client, projectID, environment, secretPath, testSecrets)

	// Cleanup: delete test secrets after test completes using batch delete
	defer DeleteInfisicalSecretsBatch(ctx, t, client, projectID, environment, secretPath, []string{secretKey1, secretKey2, secretKey3})

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: infisical
    id: infisical-test
    project_id: %s
    environment: %s
    path: %s
    keys:
      %s: %s
      %s: %s
      %s: ==
`, projectID, environment, secretPath, secretKey1, secretKey1, secretKey2, secretKey2, secretKey3)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load config
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Create collector
	collector := secrets.NewCollector(cfg)

	// Collect secrets from Infisical provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify Infisical secrets
	expectedSecrets := map[string]string{
		secretKey1: secretValue1,
		secretKey2: secretValue2,
		secretKey3: secretValue3, // Same name (==)
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from Infisical not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from Infisical: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}
}

// TestE2E_Infisical_NoKeys tests the Infisical provider without key mappings
func TestE2E_Infisical_NoKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires real Infisical service")
	}
	ctx := context.Background()

	// Setup Infisical client
	client := SetupInfisicalClient(ctx, t)

	// Get test project ID and environment from environment variables
	projectID := GetInfisicalTestProjectID(t)
	environment := GetInfisicalTestEnvironment(t)

	// Test path and secrets
	secretPath := "/"
	secretKey1 := "INFISICAL_API_KEY"
	secretValue1 := "infisical-secret-api-key-67890"
	secretKey2 := "INFISICAL_DB_PASSWORD"
	secretValue2 := "infisical-secret-db-password"
	secretKey3 := "INFISICAL_CONFIG"
	secretValue3 := "infisical-config-value"

	// Setup test secrets using batch create
	testSecrets := map[string]string{
		secretKey1: secretValue1,
		secretKey2: secretValue2,
		secretKey3: secretValue3,
	}
	SetupInfisicalSecretsBatch(ctx, t, client, projectID, environment, secretPath, testSecrets)

	// Cleanup: delete test secrets after test completes using batch delete
	defer DeleteInfisicalSecretsBatch(ctx, t, client, projectID, environment, secretPath, []string{secretKey1, secretKey2, secretKey3})

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: infisical
    id: infisical-test
    project_id: %s
    environment: %s
    path: %s
`, projectID, environment, secretPath)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load config
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Create collector
	collector := secrets.NewCollector(cfg)

	// Collect secrets from Infisical provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify Infisical secrets (should use original key names)
	expectedSecrets := map[string]string{
		secretKey1: secretValue1,
		secretKey2: secretValue2,
		secretKey3: secretValue3,
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from Infisical not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from Infisical: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}
}

// TestE2E_Infisical_WithOptionalParams tests the Infisical provider with optional parameters
func TestE2E_Infisical_WithOptionalParams(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires real Infisical service")
	}
	ctx := context.Background()

	// Setup Infisical client
	client := SetupInfisicalClient(ctx, t)

	// Get test project ID and environment from environment variables
	projectID := GetInfisicalTestProjectID(t)
	environment := GetInfisicalTestEnvironment(t)

	// Test path and secrets
	secretPath := "/"
	secretKey1 := "INFISICAL_API_KEY"
	secretValue1 := "infisical-secret-api-key-optional"

	// Setup test secrets (create or update them)
	SetupInfisicalSecret(ctx, t, client, projectID, environment, secretPath, secretKey1, secretValue1)

	// Cleanup: delete test secret after test completes
	defer DeleteInfisicalSecret(ctx, t, client, projectID, environment, secretPath, secretKey1)

	// Create temporary config file with optional parameters
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: infisical
    id: infisical-test
    project_id: %s
    environment: %s
    path: %s
    recursive: true
    include_imports: true
    expand_secrets: false
`, projectID, environment, secretPath)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load config
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Create collector
	collector := secrets.NewCollector(cfg)

	// Collect secrets from Infisical provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify we got at least the expected secret
	actualValue, exists := collectedSecrets[secretKey1]
	if !exists {
		t.Errorf("Expected secret '%s' from Infisical not found", secretKey1)
	} else if actualValue != secretValue1 {
		t.Errorf("Secret '%s' from Infisical: expected '%s', got '%s'", secretKey1, secretValue1, actualValue)
	}
}

// TestE2E_Infisical_VerifySecretExists tests that the test setup can verify secrets exist
func TestE2E_Infisical_VerifySecretExists(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires real Infisical service")
	}
	ctx := context.Background()

	// Setup Infisical client
	client := SetupInfisicalClient(ctx, t)

	// Get test project ID and environment from environment variables
	projectID := GetInfisicalTestProjectID(t)
	environment := GetInfisicalTestEnvironment(t)

	// Test path and secret
	secretPath := "/"
	secretKey := "INFISICAL_TEST_SECRET"
	secretValue := "test-value-for-verification"

	// Setup test secret
	SetupInfisicalSecret(ctx, t, client, projectID, environment, secretPath, secretKey, secretValue)

	// Cleanup: delete test secret after test completes
	defer DeleteInfisicalSecret(ctx, t, client, projectID, environment, secretPath, secretKey)

	// Verify the secret exists
	VerifyInfisicalSecretExists(ctx, t, client, projectID, environment, secretPath, secretKey)
}

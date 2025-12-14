package end2end

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dirathea/sstart/internal/config"
	_ "github.com/dirathea/sstart/internal/provider/vault"
	"github.com/dirathea/sstart/internal/secrets"
)

// TestE2E_OpenBao_WithKeys tests the Vault provider (used for OpenBao) with key mappings
func TestE2E_OpenBao_WithKeys(t *testing.T) {
	ctx := context.Background()

	// Setup OpenBao container
	openbaoContainer := SetupOpenBao(ctx, t)
	defer func() {
		if err := openbaoContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate OpenBao container: %v", err)
		}
	}()

	// Write secret to OpenBao
	openbaoPath := "myapp/config"
	openbaoSecretData := map[string]interface{}{
		"OPENBAO_API_KEY":     "openbao-secret-api-key-67890",
		"OPENBAO_DB_PASSWORD": "openbao-secret-db-password",
		"OPENBAO_CONFIG":      "openbao-config-value",
	}
	SetupOpenBaoSecret(ctx, t, openbaoContainer, openbaoPath, openbaoSecretData)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: vault
    id: openbao-test
    path: %s
    address: %s
    token: test-token
    mount: secret
    keys:
      OPENBAO_API_KEY: OPENBAO_API_KEY
      OPENBAO_DB_PASSWORD: OPENBAO_DB_PASSWORD
      OPENBAO_CONFIG: ==
`, openbaoPath, openbaoContainer.Address)

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

	// Collect secrets from OpenBao provider (using vault provider)
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify OpenBao secrets
	expectedOpenBaoSecrets := map[string]string{
		"OPENBAO_API_KEY":     "openbao-secret-api-key-67890",
		"OPENBAO_DB_PASSWORD": "openbao-secret-db-password",
		"OPENBAO_CONFIG":      "openbao-config-value", // Same name (==)
	}

	for key, expectedValue := range expectedOpenBaoSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from OpenBao not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from OpenBao: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedOpenBaoSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from OpenBao provider", len(collectedSecrets))
}

// TestE2E_OpenBao_NoKeys tests the Vault provider (used for OpenBao) without key mappings
func TestE2E_OpenBao_NoKeys(t *testing.T) {
	ctx := context.Background()

	// Setup OpenBao container
	openbaoContainer := SetupOpenBao(ctx, t)
	defer func() {
		if err := openbaoContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate OpenBao container: %v", err)
		}
	}()

	// Write secret to OpenBao
	openbaoPath := "myapp/no-keys"
	openbaoSecretData := map[string]interface{}{
		"OPENBAO_API_KEY":     "openbao-secret-api-key-67890",
		"OPENBAO_DB_PASSWORD": "openbao-secret-db-password",
		"OPENBAO_CONFIG":      "openbao-config-value",
	}
	SetupOpenBaoSecret(ctx, t, openbaoContainer, openbaoPath, openbaoSecretData)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: vault
    id: openbao-test
    path: %s
    address: %s
    token: test-token
    mount: secret
`, openbaoPath, openbaoContainer.Address)

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

	// Collect secrets from OpenBao provider (using vault provider)
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify OpenBao secrets (should use original key names)
	expectedOpenBaoSecrets := map[string]string{
		"OPENBAO_API_KEY":     "openbao-secret-api-key-67890",
		"OPENBAO_DB_PASSWORD": "openbao-secret-db-password",
		"OPENBAO_CONFIG":      "openbao-config-value",
	}

	for key, expectedValue := range expectedOpenBaoSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from OpenBao not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from OpenBao: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedOpenBaoSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from OpenBao provider without key mappings", len(collectedSecrets))
}

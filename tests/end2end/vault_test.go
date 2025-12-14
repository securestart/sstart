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

// TestE2E_Vault_WithKeys tests the Vault provider with key mappings
func TestE2E_Vault_WithKeys(t *testing.T) {
	ctx := context.Background()

	// Setup Vault container
	vaultContainer := SetupVault(ctx, t)
	defer func() {
		if err := vaultContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate vault container: %v", err)
		}
	}()

	// Write secret to Vault
	vaultPath := "myapp/config"
	vaultSecretData := map[string]interface{}{
		"VAULT_API_KEY":     "vault-secret-api-key-67890",
		"VAULT_DB_PASSWORD": "vault-secret-db-password",
		"VAULT_CONFIG":      "vault-config-value",
	}
	SetupVaultSecret(ctx, t, vaultContainer, vaultPath, vaultSecretData)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: vault
    id: vault-test
    path: %s
    address: %s
    token: test-token
    mount: secret
    keys:
      VAULT_API_KEY: VAULT_API_KEY
      VAULT_DB_PASSWORD: VAULT_DB_PASSWORD
      VAULT_CONFIG: ==
`, vaultPath, vaultContainer.Address)

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

	// Collect secrets from Vault provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify Vault secrets
	expectedVaultSecrets := map[string]string{
		"VAULT_API_KEY":     "vault-secret-api-key-67890",
		"VAULT_DB_PASSWORD": "vault-secret-db-password",
		"VAULT_CONFIG":      "vault-config-value", // Same name (==)
	}

	for key, expectedValue := range expectedVaultSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from Vault not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from Vault: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedVaultSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from Vault provider", len(collectedSecrets))
}

// TestE2E_Vault_NoKeys tests the Vault provider without key mappings
func TestE2E_Vault_NoKeys(t *testing.T) {
	ctx := context.Background()

	// Setup Vault container
	vaultContainer := SetupVault(ctx, t)
	defer func() {
		if err := vaultContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate vault container: %v", err)
		}
	}()

	// Write secret to Vault
	vaultPath := "myapp/no-keys"
	vaultSecretData := map[string]interface{}{
		"VAULT_API_KEY":     "vault-secret-api-key-67890",
		"VAULT_DB_PASSWORD": "vault-secret-db-password",
		"VAULT_CONFIG":      "vault-config-value",
	}
	SetupVaultSecret(ctx, t, vaultContainer, vaultPath, vaultSecretData)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: vault
    id: vault-test
    path: %s
    address: %s
    token: test-token
    mount: secret
`, vaultPath, vaultContainer.Address)

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

	// Collect secrets from Vault provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify Vault secrets (should use original key names)
	expectedVaultSecrets := map[string]string{
		"VAULT_API_KEY":     "vault-secret-api-key-67890",
		"VAULT_DB_PASSWORD": "vault-secret-db-password",
		"VAULT_CONFIG":      "vault-config-value",
	}

	for key, expectedValue := range expectedVaultSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from Vault not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from Vault: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedVaultSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from Vault provider without key mappings", len(collectedSecrets))
}

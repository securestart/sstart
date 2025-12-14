package end2end

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dirathea/sstart/internal/config"
	_ "github.com/dirathea/sstart/internal/provider/azurekeyvault"
	"github.com/dirathea/sstart/internal/secrets"
)

// TestE2E_AzureKeyVault_WithKeys tests the Azure Key Vault provider using emulator with key mappings
func TestE2E_AzureKeyVault_WithKeys(t *testing.T) {
	ctx := context.Background()

	// Setup Azure Key Vault emulator
	akvContainer := SetupAzureKeyVault(ctx, t)
	defer func() {
		if err := akvContainer.Cleanup(); err != nil {
			t.Errorf("Failed to cleanup Azure Key Vault container: %v", err)
		}
	}()

	// Set up Azure Key Vault secret
	secretName := "test-secret"
	secretData := map[string]interface{}{
		"API_KEY":     "azure-secret-api-key-12345",
		"DB_PASSWORD": "azure-secret-db-password",
		"JWT_SECRET":  "azure-secret-jwt-token",
	}
	SetupAzureKeyVaultSecret(ctx, t, akvContainer, secretName, secretData)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: azure_keyvault
    id: azure-test
    vault_url: %s
    secret_name: %s
    keys:
      API_KEY: AZURE_API_KEY
      DB_PASSWORD: AZURE_DB_PASSWORD
      JWT_SECRET: ==
`, akvContainer.VaultURL, secretName)

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

	// Collect secrets from Azure Key Vault provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify Azure Key Vault secrets
	expectedAzureSecrets := map[string]string{
		"AZURE_API_KEY":     "azure-secret-api-key-12345",
		"AZURE_DB_PASSWORD": "azure-secret-db-password",
		"JWT_SECRET":        "azure-secret-jwt-token", // Same name (==)
	}

	for key, expectedValue := range expectedAzureSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from Azure Key Vault not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from Azure Key Vault: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedAzureSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from Azure Key Vault provider", len(collectedSecrets))
}

// TestE2E_AzureKeyVault_NoKeys tests the Azure Key Vault provider using emulator without key mappings
func TestE2E_AzureKeyVault_NoKeys(t *testing.T) {
	ctx := context.Background()

	// Setup Azure Key Vault emulator
	akvContainer := SetupAzureKeyVault(ctx, t)
	defer func() {
		if err := akvContainer.Cleanup(); err != nil {
			t.Errorf("Failed to cleanup Azure Key Vault container: %v", err)
		}
	}()

	// Set up Azure Key Vault secret
	secretName := "test-secret-no-keys"
	secretData := map[string]interface{}{
		"API_KEY":     "azure-secret-api-key-12345",
		"DB_PASSWORD": "azure-secret-db-password",
		"JWT_SECRET":  "azure-secret-jwt-token",
	}
	SetupAzureKeyVaultSecret(ctx, t, akvContainer, secretName, secretData)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: azure_keyvault
    id: azure-test
    vault_url: %s
    secret_name: %s
`, akvContainer.VaultURL, secretName)

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

	// Collect secrets from Azure Key Vault provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify Azure Key Vault secrets (should use original key names)
	expectedAzureSecrets := map[string]string{
		"API_KEY":     "azure-secret-api-key-12345",
		"DB_PASSWORD": "azure-secret-db-password",
		"JWT_SECRET":  "azure-secret-jwt-token",
	}

	for key, expectedValue := range expectedAzureSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from Azure Key Vault not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from Azure Key Vault: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedAzureSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from Azure Key Vault provider without key mappings", len(collectedSecrets))
}

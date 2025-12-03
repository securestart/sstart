package end2end

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dirathea/sstart/internal/config"
	_ "github.com/dirathea/sstart/internal/provider/bitwarden"
	"github.com/dirathea/sstart/internal/secrets"
)

// TestE2E_Bitwarden_NoteFormat tests the Bitwarden provider with Note format (JSON)
func TestE2E_Bitwarden_NoteFormat(t *testing.T) {
	ctx := context.Background()

	// Setup Vaultwarden container
	vaultwarden := SetupVaultwarden(ctx, t)
	defer func() {
		if err := vaultwarden.Cleanup(); err != nil {
			t.Errorf("Failed to terminate vaultwarden container: %v", err)
		}
	}()

	// Create a secret with note content as JSON
	noteContent := `{
		"API_KEY": "bitwarden-note-api-key-12345",
		"DB_PASSWORD": "bitwarden-note-db-password",
		"JWT_SECRET": "bitwarden-note-jwt-token"
	}`
	itemID, accessToken := SetupVaultwardenSecret(ctx, t, vaultwarden, "test-secret-note", noteContent, nil)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: bitwarden
    id: bitwarden-test
    server_url: %s
    access_token: %s
    secret_id: %s
    format: note
    keys:
      API_KEY: BITWARDEN_API_KEY
      DB_PASSWORD: BITWARDEN_DB_PASSWORD
      JWT_SECRET: ==
`, vaultwarden.URL, accessToken, itemID)

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

	// Collect secrets from Bitwarden provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify Bitwarden secrets
	expectedSecrets := map[string]string{
		"BITWARDEN_API_KEY":     "bitwarden-note-api-key-12345",
		"BITWARDEN_DB_PASSWORD": "bitwarden-note-db-password",
		"JWT_SECRET":             "bitwarden-note-jwt-token", // Same name (==)
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from Bitwarden not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from Bitwarden: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from Bitwarden provider (Note format)", len(collectedSecrets))
}

// TestE2E_Bitwarden_FieldsFormat tests the Bitwarden provider with Fields format (key-value pairs)
func TestE2E_Bitwarden_FieldsFormat(t *testing.T) {
	ctx := context.Background()

	// Setup Vaultwarden container
	vaultwarden := SetupVaultwarden(ctx, t)
	defer func() {
		if err := vaultwarden.Cleanup(); err != nil {
			t.Errorf("Failed to terminate vaultwarden container: %v", err)
		}
	}()

	// Create a secret with custom fields
	fields := map[string]string{
		"API_KEY":     "bitwarden-field-api-key-67890",
		"DB_PASSWORD": "bitwarden-field-db-password",
		"JWT_SECRET":  "bitwarden-field-jwt-token",
	}
	itemID, accessToken := SetupVaultwardenSecret(ctx, t, vaultwarden, "test-secret-fields", "", fields)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: bitwarden
    id: bitwarden-test
    server_url: %s
    access_token: %s
    secret_id: %s
    format: fields
    keys:
      API_KEY: BITWARDEN_API_KEY
      DB_PASSWORD: BITWARDEN_DB_PASSWORD
      JWT_SECRET: ==
`, vaultwarden.URL, accessToken, itemID)

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

	// Collect secrets from Bitwarden provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify Bitwarden secrets
	expectedSecrets := map[string]string{
		"BITWARDEN_API_KEY":     "bitwarden-field-api-key-67890",
		"BITWARDEN_DB_PASSWORD": "bitwarden-field-db-password",
		"JWT_SECRET":             "bitwarden-field-jwt-token", // Same name (==)
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from Bitwarden not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from Bitwarden: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from Bitwarden provider (Fields format)", len(collectedSecrets))
}

// TestE2E_Bitwarden_NoKeys tests the Bitwarden provider without key mappings
func TestE2E_Bitwarden_NoKeys(t *testing.T) {
	ctx := context.Background()

	// Setup Vaultwarden container
	vaultwarden := SetupVaultwarden(ctx, t)
	defer func() {
		if err := vaultwarden.Cleanup(); err != nil {
			t.Errorf("Failed to terminate vaultwarden container: %v", err)
		}
	}()

	// Create a secret with note content as JSON
	noteContent := `{
		"API_KEY": "bitwarden-no-keys-api-key",
		"DB_PASSWORD": "bitwarden-no-keys-db-password",
		"JWT_SECRET": "bitwarden-no-keys-jwt-token"
	}`
	itemID, accessToken := SetupVaultwardenSecret(ctx, t, vaultwarden, "test-secret-no-keys", noteContent, nil)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: bitwarden
    id: bitwarden-test
    server_url: %s
    access_token: %s
    secret_id: %s
    format: note
`, vaultwarden.URL, accessToken, itemID)

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

	// Collect secrets from Bitwarden provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify Bitwarden secrets (should use original key names)
	expectedSecrets := map[string]string{
		"API_KEY":     "bitwarden-no-keys-api-key",
		"DB_PASSWORD": "bitwarden-no-keys-db-password",
		"JWT_SECRET":  "bitwarden-no-keys-jwt-token",
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from Bitwarden not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from Bitwarden: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from Bitwarden provider without key mappings", len(collectedSecrets))
}

// TestE2E_Bitwarden_EmailPasswordAuth tests the Bitwarden provider with email/password authentication
func TestE2E_Bitwarden_EmailPasswordAuth(t *testing.T) {
	ctx := context.Background()

	// Setup Vaultwarden container
	vaultwarden := SetupVaultwarden(ctx, t)
	defer func() {
		if err := vaultwarden.Cleanup(); err != nil {
			t.Errorf("Failed to terminate vaultwarden container: %v", err)
		}
	}()

	// Create a secret with note content as JSON
	noteContent := `{
		"API_KEY": "bitwarden-email-auth-api-key",
		"DB_PASSWORD": "bitwarden-email-auth-db-password"
	}`
	itemID, _ := SetupVaultwardenSecret(ctx, t, vaultwarden, "test-secret-email-auth", noteContent, nil)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: bitwarden
    id: bitwarden-test
    server_url: %s
    email: %s
    password: %s
    secret_id: %s
    format: note
`, vaultwarden.URL, vaultwarden.Email, vaultwarden.Password, itemID)

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

	// Collect secrets from Bitwarden provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify Bitwarden secrets
	expectedSecrets := map[string]string{
		"API_KEY":     "bitwarden-email-auth-api-key",
		"DB_PASSWORD": "bitwarden-email-auth-db-password",
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from Bitwarden not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from Bitwarden: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	t.Logf("Successfully collected %d secrets from Bitwarden provider with email/password auth", len(collectedSecrets))
}

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

// Tests for bitwarden (Personal Bitwarden using CLI REST API)
// These tests require:
// 1. Bitwarden CLI (bw) installed and available in PATH
// 2. BW_CLIENTID and BW_CLIENTSECRET environment variables set
// 3. BW_PASSWORD environment variable set (master password for unlocking vault)

// TestE2E_Bitwarden_CLI_FieldsFormat tests the personal Bitwarden provider with fields format
func TestE2E_Bitwarden_CLI_FieldsFormat(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires real Bitwarden service")
	}
	ctx := context.Background()

	// Setup Bitwarden CLI (login, unlock, start bw serve)
	session, _ := SetupBitwardenCLI(ctx, t)

	// Set BW_SESSION for the provider
	os.Setenv("BW_SESSION", session)
	defer os.Unsetenv("BW_SESSION")

	// Create a test item with custom fields (using Secure Note type 2)
	fields := map[string]string{
		"API_KEY":     "test-api-key-12345",
		"DB_PASSWORD": "test-db-password-67890",
	}
	itemID := SetupBitwardenItem(ctx, t, "sstart-test-fields", 2, "", fields, "", "")

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: bitwarden
    id: bitwarden-test
    item_id: %s
    format: fields
    keys:
      API_KEY: BITWARDEN_API_KEY
      DB_PASSWORD: BITWARDEN_DB_PASSWORD
`, itemID)

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

	// Verify we got the expected secrets
	expectedSecrets := map[string]string{
		"BITWARDEN_API_KEY":     "test-api-key-12345",
		"BITWARDEN_DB_PASSWORD": "test-db-password-67890",
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

	t.Logf("Successfully collected %d secrets from Bitwarden CLI provider (Fields format)", len(collectedSecrets))
}

// TestE2E_Bitwarden_CLI_NoteFormat tests the personal Bitwarden provider with note format
func TestE2E_Bitwarden_CLI_NoteFormat(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires real Bitwarden service")
	}
	ctx := context.Background()

	// Setup Bitwarden CLI (login, unlock, start bw serve)
	session, _ := SetupBitwardenCLI(ctx, t)

	// Set BW_SESSION for the provider
	os.Setenv("BW_SESSION", session)
	defer os.Unsetenv("BW_SESSION")

	// Create a test item with JSON in notes
	noteContent := `{
		"API_KEY": "test-note-api-key-12345",
		"DB_PASSWORD": "test-note-db-password",
		"JWT_SECRET": "test-note-jwt-token"
	}`
	itemID := SetupBitwardenItem(ctx, t, "sstart-test-note", 2, noteContent, nil, "", "")

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: bitwarden
    id: bitwarden-test
    item_id: %s
    format: note
`, itemID)

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

	// Verify we got the expected secrets
	expectedSecrets := map[string]string{
		"API_KEY":     "test-note-api-key-12345",
		"DB_PASSWORD": "test-note-db-password",
		"JWT_SECRET":  "test-note-jwt-token",
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

	t.Logf("Successfully collected %d secrets from Bitwarden CLI provider (Note format)", len(collectedSecrets))
}

// TestE2E_Bitwarden_CLI_BothFormat tests the personal Bitwarden provider with both format
// This tests that fields take precedence over notes when there are duplicate keys
func TestE2E_Bitwarden_CLI_BothFormat(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires real Bitwarden service")
	}
	ctx := context.Background()

	// Setup Bitwarden CLI (login, unlock, start bw serve)
	session, _ := SetupBitwardenCLI(ctx, t)

	// Set BW_SESSION for the provider
	os.Setenv("BW_SESSION", session)
	defer os.Unsetenv("BW_SESSION")

	// Create a test item with both JSON in notes and custom fields
	// Note: We'll use a duplicate key to test that fields take precedence
	noteContent := `{
		"API_KEY": "test-note-api-key-12345",
		"DB_PASSWORD": "test-note-db-password",
		"JWT_SECRET": "test-note-jwt-token"
	}`
	// Fields will override API_KEY and DB_PASSWORD from notes
	fields := map[string]string{
		"API_KEY":     "test-field-api-key-override",
		"DB_PASSWORD": "test-field-db-password-override",
		"FIELD_ONLY":   "field-only-value",
	}
	itemID := SetupBitwardenItem(ctx, t, "sstart-test-both", 2, noteContent, fields, "", "")

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: bitwarden
    id: bitwarden-test
    item_id: %s
    format: both
`, itemID)

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

	// Verify we got the expected secrets
	// Fields should take precedence over notes for duplicate keys
	expectedSecrets := map[string]string{
		"API_KEY":     "test-field-api-key-override",    // From fields (overrides note)
		"DB_PASSWORD": "test-field-db-password-override", // From fields (overrides note)
		"JWT_SECRET":  "test-note-jwt-token",             // From notes (no field override)
		"FIELD_ONLY":  "field-only-value",               // From fields only
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

	t.Logf("Successfully collected %d secrets from Bitwarden CLI provider (Both format)", len(collectedSecrets))
}

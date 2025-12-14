package end2end

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dirathea/sstart/internal/config"
	_ "github.com/dirathea/sstart/internal/provider/onepassword"
	"github.com/dirathea/sstart/internal/secrets"
)

// getKeys returns a slice of keys from a map for error messages
func getKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Tests for 1Password provider
// These tests require:
// 1. OP_SERVICE_ACCOUNT_TOKEN environment variable set
// 2. A test vault named "sstart-test" (or set OP_TEST_VAULT_NAME)
// 3. The service account must have access to the test vault

// TestE2E_OnePassword_SectionField tests fetching a field from a section
func TestE2E_OnePassword_SectionField(t *testing.T) {
	ctx := context.Background()

	// Setup 1Password client
	client := SetupOnePasswordClient(ctx, t)

	// Get test vault
	vaultName := os.Getenv("OP_TEST_VAULT_NAME")
	if vaultName == "" {
		vaultName = "sstart-test"
	}
	vaultID := SetupOnePasswordVault(ctx, t, client, vaultName)

	// Create a test item with a section containing fields
	itemTitle := "sstart-test-section-field"
	sections := map[string]map[string]string{
		"Database": {
			"HOST":     "db.example.com",
			"PORT":     "5432",
			"USERNAME": "dbuser",
		},
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, nil, sections)
	defer CleanupOnePasswordItem(ctx, t, client, vaultID, itemID)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	onePasswordRef := fmt.Sprintf("op://%s/%s/Database/HOST", vaultName, itemTitle)
	configYAML := fmt.Sprintf(`
providers:
  - kind: 1password
    id: onepassword-test
    ref: %s
`, onePasswordRef)

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

	// Collect secrets from 1Password provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify we got the expected secret
	expectedValue := "db.example.com"
	actualValue, exists := collectedSecrets["HOST"]
	if !exists {
		t.Errorf("Expected secret 'HOST' from 1Password not found. Available keys: %v", getKeys(collectedSecrets))
	} else if actualValue != expectedValue {
		t.Errorf("Secret 'HOST' from 1Password: expected '%s', got '%s'", expectedValue, actualValue)
	}

	// Verify that we have exactly one secret
	if len(collectedSecrets) != 1 {
		t.Errorf("Expected 1 secret, got %d. Secrets: %v", len(collectedSecrets), collectedSecrets)
	}
}

// TestE2E_OnePassword_TopLevelField tests fetching a top-level field (not in any section)
func TestE2E_OnePassword_TopLevelField(t *testing.T) {
	ctx := context.Background()

	// Setup 1Password client
	client := SetupOnePasswordClient(ctx, t)

	// Get test vault
	vaultName := os.Getenv("OP_TEST_VAULT_NAME")
	if vaultName == "" {
		vaultName = "sstart-test"
	}
	vaultID := SetupOnePasswordVault(ctx, t, client, vaultName)

	// Create a test item with top-level fields (not in any section)
	itemTitle := "sstart-test-top-level-field"
	fields := map[string]string{
		"API_KEY":    "test-api-key-top-level",
		"JWT_SECRET": "test-jwt-secret-top-level",
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, fields, nil)
	defer CleanupOnePasswordItem(ctx, t, client, vaultID, itemID)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	onePasswordRef := fmt.Sprintf("op://%s/%s/API_KEY", vaultName, itemTitle)
	configYAML := fmt.Sprintf(`
providers:
  - kind: 1password
    id: onepassword-test
    ref: %s
`, onePasswordRef)

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

	// Collect secrets from 1Password provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify we got the expected secret
	expectedValue := "test-api-key-top-level"
	actualValue, exists := collectedSecrets["API_KEY"]
	if !exists {
		t.Errorf("Expected secret 'API_KEY' from 1Password not found. Available keys: %v", getKeys(collectedSecrets))
	} else if actualValue != expectedValue {
		t.Errorf("Secret 'API_KEY' from 1Password: expected '%s', got '%s'", expectedValue, actualValue)
	}

	// Verify that we have exactly one secret
	if len(collectedSecrets) != 1 {
		t.Errorf("Expected 1 secret, got %d. Secrets: %v", len(collectedSecrets), collectedSecrets)
	}
}

// TestE2E_OnePassword_WholeSection tests fetching a whole section from 1Password
func TestE2E_OnePassword_WholeSection(t *testing.T) {
	ctx := context.Background()

	// Setup 1Password client
	client := SetupOnePasswordClient(ctx, t)

	// Get test vault
	vaultName := os.Getenv("OP_TEST_VAULT_NAME")
	if vaultName == "" {
		vaultName = "sstart-test"
	}
	vaultID := SetupOnePasswordVault(ctx, t, client, vaultName)

	// Create a test item with a section containing multiple fields
	itemTitle := "sstart-test-whole-section"
	sections := map[string]map[string]string{
		"Database": {
			"HOST":     "db.example.com",
			"PORT":     "5432",
			"USERNAME": "dbuser",
			"PASSWORD": "dbpass123",
		},
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, nil, sections)
	defer CleanupOnePasswordItem(ctx, t, client, vaultID, itemID)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	onePasswordRef := fmt.Sprintf("op://%s/%s/Database", vaultName, itemTitle)
	configYAML := fmt.Sprintf(`
providers:
  - kind: 1password
    id: onepassword-test
    ref: %s
`, onePasswordRef)

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

	// Collect secrets from 1Password provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify we got all expected secrets from the section
	expectedSecrets := map[string]string{
		"HOST":     "db.example.com",
		"PORT":     "5432",
		"USERNAME": "dbuser",
		"PASSWORD": "dbpass123",
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from 1Password section not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from 1Password: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	if len(collectedSecrets) != len(expectedSecrets) {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", len(expectedSecrets), len(collectedSecrets), collectedSecrets)
	}
}

// TestE2E_OnePassword_WholeItem_OnlyTopLevelFields tests fetching a whole item that has only top-level fields (no sections)
func TestE2E_OnePassword_WholeItem_OnlyTopLevelFields(t *testing.T) {
	ctx := context.Background()

	// Setup 1Password client
	client := SetupOnePasswordClient(ctx, t)

	// Get test vault
	vaultName := os.Getenv("OP_TEST_VAULT_NAME")
	if vaultName == "" {
		vaultName = "sstart-test"
	}
	vaultID := SetupOnePasswordVault(ctx, t, client, vaultName)

	// Create a test item with ONLY top-level fields (no sections at all)
	itemTitle := "sstart-test-whole-item-top-level-only"
	fields := map[string]string{
		"API_KEY":    "test-api-key-only",
		"JWT_SECRET": "test-jwt-secret-only",
		"DB_URL":     "postgresql://localhost:5432/mydb",
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, fields, nil)
	defer CleanupOnePasswordItem(ctx, t, client, vaultID, itemID)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	onePasswordRef := fmt.Sprintf("op://%s/%s", vaultName, itemTitle)
	configYAML := fmt.Sprintf(`
providers:
  - kind: 1password
    id: onepassword-test
    ref: %s
`, onePasswordRef)

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

	// Collect secrets from 1Password provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify we got all expected secrets from the item
	expectedSecrets := map[string]string{
		"API_KEY":    "test-api-key-only",
		"JWT_SECRET": "test-jwt-secret-only",
		"DB_URL":     "postgresql://localhost:5432/mydb",
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from 1Password item not found. Available keys: %v", key, getKeys(collectedSecrets))
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from 1Password: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	if len(collectedSecrets) != len(expectedSecrets) {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", len(expectedSecrets), len(collectedSecrets), collectedSecrets)
	}

	// Verify that no secrets have section prefixes (since there are no sections)
	for key := range collectedSecrets {
		if strings.Contains(key, "_") {
			if _, exists := expectedSecrets[key]; !exists {
				t.Errorf("Unexpected secret key '%s' found - might have incorrect section prefix", key)
			}
		}
	}
}

// TestE2E_OnePassword_WholeItem tests fetching a whole item from 1Password
func TestE2E_OnePassword_WholeItem(t *testing.T) {
	ctx := context.Background()

	// Setup 1Password client
	client := SetupOnePasswordClient(ctx, t)

	// Get test vault
	vaultName := os.Getenv("OP_TEST_VAULT_NAME")
	if vaultName == "" {
		vaultName = "sstart-test"
	}
	vaultID := SetupOnePasswordVault(ctx, t, client, vaultName)

	// Create a test item with both top-level fields and section fields
	itemTitle := "sstart-test-whole-item"
	fields := map[string]string{
		"API_KEY":    "test-api-key-12345",
		"JWT_SECRET": "test-jwt-secret-67890",
	}
	sections := map[string]map[string]string{
		"Database": {
			"HOST":     "db.example.com",
			"PORT":     "5432",
			"USERNAME": "dbuser",
		},
		"Redis": {
			"HOST": "redis.example.com",
			"PORT": "6379",
		},
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, fields, sections)
	defer CleanupOnePasswordItem(ctx, t, client, vaultID, itemID)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	onePasswordRef := fmt.Sprintf("op://%s/%s", vaultName, itemTitle)
	configYAML := fmt.Sprintf(`
providers:
  - kind: 1password
    id: onepassword-test
    ref: %s
    use_section_prefix: true
`, onePasswordRef)

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

	// Collect secrets from 1Password provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify we got all expected secrets from the item
	expectedSecrets := map[string]string{
		"API_KEY":           "test-api-key-12345",
		"JWT_SECRET":        "test-jwt-secret-67890",
		"Database_HOST":     "db.example.com",
		"Database_PORT":     "5432",
		"Database_USERNAME": "dbuser",
		"Redis_HOST":        "redis.example.com",
		"Redis_PORT":        "6379",
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from 1Password item not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from 1Password: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	if len(collectedSecrets) != len(expectedSecrets) {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", len(expectedSecrets), len(collectedSecrets), collectedSecrets)
	}
}

// TestE2E_OnePassword_WholeItem_NoSectionPrefix tests fetching a whole item without section prefixes
func TestE2E_OnePassword_WholeItem_NoSectionPrefix(t *testing.T) {
	ctx := context.Background()

	// Setup 1Password client
	client := SetupOnePasswordClient(ctx, t)

	// Get test vault
	vaultName := os.Getenv("OP_TEST_VAULT_NAME")
	if vaultName == "" {
		vaultName = "sstart-test"
	}
	vaultID := SetupOnePasswordVault(ctx, t, client, vaultName)

	// Create a test item with both top-level fields and section fields
	itemTitle := "sstart-test-whole-item-no-prefix"
	fields := map[string]string{
		"API_KEY":    "test-api-key-no-prefix",
		"JWT_SECRET": "test-jwt-secret-no-prefix",
	}
	sections := map[string]map[string]string{
		"Database": {
			"HOST":     "db.example.com",
			"PORT":     "5432",
			"USERNAME": "dbuser",
		},
		"Redis": {
			"HOST": "redis.example.com",
			"PORT": "6379",
		},
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, fields, sections)
	defer CleanupOnePasswordItem(ctx, t, client, vaultID, itemID)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	onePasswordRef := fmt.Sprintf("op://%s/%s", vaultName, itemTitle)
	configYAML := fmt.Sprintf(`
providers:
  - kind: 1password
    id: onepassword-test
    ref: %s
    use_section_prefix: false
`, onePasswordRef)

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

	// Collect secrets from 1Password provider
	collectedSecrets, err := collector.Collect(ctx, nil)

	// This should fail due to collisions (HOST and PORT exist in both Database and Redis sections)
	if err == nil {
		t.Fatalf("Expected error due to collision (HOST and PORT in both Database and Redis sections), but got success. Secrets: %v", collectedSecrets)
	}

	// Verify the error message mentions collision
	if !strings.Contains(err.Error(), "collision") {
		t.Errorf("Expected error message to mention 'collision', got: %v", err)
	}
}

// TestE2E_OnePassword_WholeSection_NoSectionPrefix tests fetching a whole section without section prefix
func TestE2E_OnePassword_WholeSection_NoSectionPrefix(t *testing.T) {
	ctx := context.Background()

	// Setup 1Password client
	client := SetupOnePasswordClient(ctx, t)

	// Get test vault
	vaultName := os.Getenv("OP_TEST_VAULT_NAME")
	if vaultName == "" {
		vaultName = "sstart-test"
	}
	vaultID := SetupOnePasswordVault(ctx, t, client, vaultName)

	// Create a test item with a section containing multiple fields
	itemTitle := "sstart-test-whole-section-no-prefix"
	sections := map[string]map[string]string{
		"Database": {
			"HOST":     "db.example.com",
			"PORT":     "5432",
			"USERNAME": "dbuser",
			"PASSWORD": "dbpass123",
		},
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, nil, sections)
	defer CleanupOnePasswordItem(ctx, t, client, vaultID, itemID)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	onePasswordRef := fmt.Sprintf("op://%s/%s/Database", vaultName, itemTitle)
	configYAML := fmt.Sprintf(`
providers:
  - kind: 1password
    id: onepassword-test
    ref: %s
    use_section_prefix: false
`, onePasswordRef)

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

	// Collect secrets from 1Password provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify we got all expected secrets from the section
	expectedSecrets := map[string]string{
		"HOST":     "db.example.com",
		"PORT":     "5432",
		"USERNAME": "dbuser",
		"PASSWORD": "dbpass123",
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from 1Password section not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from 1Password: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	if len(collectedSecrets) != len(expectedSecrets) {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", len(expectedSecrets), len(collectedSecrets), collectedSecrets)
	}

	// Verify that no secrets have section prefixes
	for key := range collectedSecrets {
		if strings.HasPrefix(key, "Database_") {
			t.Errorf("Unexpected section prefix found in key '%s' (use_section_prefix is false)", key)
		}
	}
}

// TestE2E_OnePassword_SectionField_NoSectionPrefix tests fetching a field from a section without section prefix
func TestE2E_OnePassword_SectionField_NoSectionPrefix(t *testing.T) {
	ctx := context.Background()

	// Setup 1Password client
	client := SetupOnePasswordClient(ctx, t)

	// Get test vault
	vaultName := os.Getenv("OP_TEST_VAULT_NAME")
	if vaultName == "" {
		vaultName = "sstart-test"
	}
	vaultID := SetupOnePasswordVault(ctx, t, client, vaultName)

	// Create a test item with a section containing fields
	itemTitle := "sstart-test-section-field-no-prefix"
	sections := map[string]map[string]string{
		"Database": {
			"HOST":     "db.example.com",
			"PORT":     "5432",
			"USERNAME": "dbuser",
		},
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, nil, sections)
	defer CleanupOnePasswordItem(ctx, t, client, vaultID, itemID)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	onePasswordRef := fmt.Sprintf("op://%s/%s/Database/HOST", vaultName, itemTitle)
	configYAML := fmt.Sprintf(`
providers:
  - kind: 1password
    id: onepassword-test
    ref: %s
    use_section_prefix: false
`, onePasswordRef)

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

	// Collect secrets from 1Password provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify we got the expected secret
	expectedValue := "db.example.com"
	actualValue, exists := collectedSecrets["HOST"]
	if !exists {
		t.Errorf("Expected secret 'HOST' from 1Password not found. Available keys: %v", getKeys(collectedSecrets))
	} else if actualValue != expectedValue {
		t.Errorf("Secret 'HOST' from 1Password: expected '%s', got '%s'", expectedValue, actualValue)
	}

	// Verify that we have exactly one secret
	if len(collectedSecrets) != 1 {
		t.Errorf("Expected 1 secret, got %d. Secrets: %v", len(collectedSecrets), collectedSecrets)
	}

	// Verify that no section prefix is used
	if _, exists := collectedSecrets["Database_HOST"]; exists {
		t.Errorf("Unexpected section prefix found in key 'Database_HOST' (use_section_prefix is false)")
	}
}

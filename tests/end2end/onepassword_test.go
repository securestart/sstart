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

	t.Logf("=== Creating 1Password Item ===")
	t.Logf("Vault: %s", vaultName)
	t.Logf("Item Title: %s", itemTitle)
	t.Logf("Sections to create:")
	for sectionName, sectionFields := range sections {
		t.Logf("  Section: %s", sectionName)
		for fieldName, fieldValue := range sectionFields {
			t.Logf("    - %s: %s", fieldName, fieldValue)
		}
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, nil, sections)
	t.Logf("Created item with ID: %s", itemID)

	// Cleanup after test
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

	t.Logf("\n=== sstart Configuration ===")
	t.Logf("1Password Reference: %s (fetching all secrets)", onePasswordRef)

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

	// Collect secrets from 1Password provider
	t.Logf("\n=== Fetching secrets with sstart ===")
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	t.Logf("Secrets fetched by sstart:")
	for key, value := range collectedSecrets {
		t.Logf("  - %s: %s", key, value)
	}

	// Verify we got the expected secret
	// When fetching a specific field from a section, the key should be just the field name (no section prefix)
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

	t.Logf("\n✓ Successfully collected secret from 1Password provider (section field)")
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
	// No sections - these are top-level fields
	sections := map[string]map[string]string{}

	t.Logf("=== Creating 1Password Item ===")
	t.Logf("Vault: %s", vaultName)
	t.Logf("Item Title: %s", itemTitle)
	t.Logf("Top-level fields to create (not in any section):")
	for fieldName, fieldValue := range fields {
		t.Logf("  - %s: %s", fieldName, fieldValue)
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, fields, sections)
	t.Logf("Created item with ID: %s", itemID)

	// Cleanup after test
	defer CleanupOnePasswordItem(ctx, t, client, vaultID, itemID)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	// Fetch a specific top-level field (not in a section)
	onePasswordRef := fmt.Sprintf("op://%s/%s/API_KEY", vaultName, itemTitle)
	configYAML := fmt.Sprintf(`
providers:
  - kind: 1password
    id: onepassword-test
    ref: %s
`, onePasswordRef)

	t.Logf("\n=== sstart Configuration ===")
	t.Logf("1Password Reference: %s (fetching top-level field, not in any section)", onePasswordRef)

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

	// Collect secrets from 1Password provider
	t.Logf("\n=== Fetching secrets with sstart ===")
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	t.Logf("Secrets fetched by sstart:")
	for key, value := range collectedSecrets {
		t.Logf("  - %s: %s", key, value)
	}

	// Verify we got the expected secret
	// When fetching a top-level field (not in section), the key should be just the field name
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

	t.Logf("\n✓ Successfully collected secret from 1Password provider (top-level field, not in any section)")
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

	t.Logf("=== Creating 1Password Item ===")
	t.Logf("Vault: %s", vaultName)
	t.Logf("Item Title: %s", itemTitle)
	t.Logf("Sections to create:")
	for sectionName, sectionFields := range sections {
		t.Logf("  Section: %s", sectionName)
		for fieldName, fieldValue := range sectionFields {
			t.Logf("    - %s: %s", fieldName, fieldValue)
		}
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, nil, sections)
	t.Logf("Created item with ID: %s", itemID)

	// Cleanup after test
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

	t.Logf("\n=== sstart Configuration ===")
	t.Logf("1Password Reference: %s (fetching whole section, all secrets)", onePasswordRef)

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

	// Collect secrets from 1Password provider
	t.Logf("\n=== Fetching secrets with sstart ===")
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	t.Logf("Secrets fetched by sstart:")
	for key, value := range collectedSecrets {
		t.Logf("  - %s: %s", key, value)
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
	expectedCount := len(expectedSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("\n✓ Successfully collected %d secrets from 1Password provider (whole section)", len(collectedSecrets))
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
	// No sections
	sections := map[string]map[string]string{}

	t.Logf("=== Creating 1Password Item ===")
	t.Logf("Vault: %s", vaultName)
	t.Logf("Item Title: %s", itemTitle)
	t.Logf("Top-level fields to create (no sections):")
	for fieldName, fieldValue := range fields {
		t.Logf("  - %s: %s", fieldName, fieldValue)
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, fields, sections)
	t.Logf("Created item with ID: %s", itemID)

	// Cleanup after test
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

	t.Logf("\n=== sstart Configuration ===")
	t.Logf("1Password Reference: %s (fetching whole item with only top-level fields)", onePasswordRef)

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

	// Collect secrets from 1Password provider
	t.Logf("\n=== Fetching secrets with sstart ===")
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	t.Logf("Secrets fetched by sstart:")
	for key, value := range collectedSecrets {
		t.Logf("  - %s: %s", key, value)
	}

	// Verify we got all expected secrets from the item
	// All fields should be top-level (no section prefix)
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
	expectedCount := len(expectedSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	// Verify that no secrets have section prefixes (since there are no sections)
	for key := range collectedSecrets {
		if strings.Contains(key, "_") {
			// Check if this underscore is from a section prefix
			// If the key contains underscore but doesn't match any expected key, it might be a section prefix
			if _, exists := expectedSecrets[key]; !exists {
				t.Errorf("Unexpected secret key '%s' found - might have incorrect section prefix", key)
			}
		}
	}

	t.Logf("\n✓ Successfully collected %d secrets from 1Password provider (whole item with only top-level fields)", len(collectedSecrets))
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

	t.Logf("=== Creating 1Password Item ===")
	t.Logf("Vault: %s", vaultName)
	t.Logf("Item Title: %s", itemTitle)
	t.Logf("Top-level fields to create:")
	for fieldName, fieldValue := range fields {
		t.Logf("  - %s: %s", fieldName, fieldValue)
	}
	t.Logf("Sections to create:")
	for sectionName, sectionFields := range sections {
		t.Logf("  Section: %s", sectionName)
		for fieldName, fieldValue := range sectionFields {
			t.Logf("    - %s: %s", fieldName, fieldValue)
		}
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, fields, sections)
	t.Logf("Created item with ID: %s", itemID)

	// Cleanup after test
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

	t.Logf("\n=== sstart Configuration ===")
	t.Logf("1Password Reference: %s (fetching whole item, all secrets, use_section_prefix: true)", onePasswordRef)

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

	// Collect secrets from 1Password provider
	t.Logf("\n=== Fetching secrets with sstart ===")
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	t.Logf("Secrets fetched by sstart:")
	for key, value := range collectedSecrets {
		t.Logf("  - %s: %s", key, value)
	}

	// Verify we got all expected secrets from the item
	// Top-level fields
	expectedSecrets := map[string]string{
		"API_KEY":    "test-api-key-12345",
		"JWT_SECRET": "test-jwt-secret-67890",
		// Section fields (with section prefix)
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
	expectedCount := len(expectedSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("\n✓ Successfully collected %d secrets from 1Password provider (whole item)", len(collectedSecrets))
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

	t.Logf("=== Creating 1Password Item ===")
	t.Logf("Vault: %s", vaultName)
	t.Logf("Item Title: %s", itemTitle)
	t.Logf("Top-level fields to create:")
	for fieldName, fieldValue := range fields {
		t.Logf("  - %s: %s", fieldName, fieldValue)
	}
	t.Logf("Sections to create:")
	for sectionName, sectionFields := range sections {
		t.Logf("  Section: %s", sectionName)
		for fieldName, fieldValue := range sectionFields {
			t.Logf("    - %s: %s", fieldName, fieldValue)
		}
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, fields, sections)
	t.Logf("Created item with ID: %s", itemID)

	// Cleanup after test
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

	t.Logf("\n=== sstart Configuration ===")
	t.Logf("1Password Reference: %s (fetching whole item, use_section_prefix: false)", onePasswordRef)

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

	// Collect secrets from 1Password provider
	t.Logf("\n=== Fetching secrets with sstart ===")
	collectedSecrets, err := collector.Collect(ctx, nil)

	// This should fail due to collisions (HOST and PORT exist in both Database and Redis sections)
	if err == nil {
		t.Fatalf("Expected error due to collision (HOST and PORT in both Database and Redis sections), but got success. Secrets: %v", collectedSecrets)
	}

	// Verify the error message mentions collision
	if !strings.Contains(err.Error(), "collision") {
		t.Errorf("Expected error message to mention 'collision', got: %v", err)
	}

	t.Logf("\n✓ Correctly failed with collision error: %v", err)
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

	t.Logf("=== Creating 1Password Item ===")
	t.Logf("Vault: %s", vaultName)
	t.Logf("Item Title: %s", itemTitle)
	t.Logf("Sections to create:")
	for sectionName, sectionFields := range sections {
		t.Logf("  Section: %s", sectionName)
		for fieldName, fieldValue := range sectionFields {
			t.Logf("    - %s: %s", fieldName, fieldValue)
		}
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, nil, sections)
	t.Logf("Created item with ID: %s", itemID)

	// Cleanup after test
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

	t.Logf("\n=== sstart Configuration ===")
	t.Logf("1Password Reference: %s (fetching whole section, use_section_prefix: false)", onePasswordRef)

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

	// Collect secrets from 1Password provider
	t.Logf("\n=== Fetching secrets with sstart ===")
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	t.Logf("Secrets fetched by sstart:")
	for key, value := range collectedSecrets {
		t.Logf("  - %s: %s", key, value)
	}

	// Verify we got all expected secrets from the section
	// Without section prefix, keys should be just the field names
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
	expectedCount := len(expectedSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	// Verify that no secrets have section prefixes
	for key := range collectedSecrets {
		if strings.HasPrefix(key, "Database_") {
			t.Errorf("Unexpected section prefix found in key '%s' (use_section_prefix is false)", key)
		}
	}

	t.Logf("\n✓ Successfully collected %d secrets from 1Password provider (whole section, no section prefix)", len(collectedSecrets))
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

	t.Logf("=== Creating 1Password Item ===")
	t.Logf("Vault: %s", vaultName)
	t.Logf("Item Title: %s", itemTitle)
	t.Logf("Sections to create:")
	for sectionName, sectionFields := range sections {
		t.Logf("  Section: %s", sectionName)
		for fieldName, fieldValue := range sectionFields {
			t.Logf("    - %s: %s", fieldName, fieldValue)
		}
	}

	itemID := SetupOnePasswordItem(ctx, t, client, vaultID, itemTitle, nil, sections)
	t.Logf("Created item with ID: %s", itemID)

	// Cleanup after test
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

	t.Logf("\n=== sstart Configuration ===")
	t.Logf("1Password Reference: %s (fetching section field, use_section_prefix: false)", onePasswordRef)

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

	// Collect secrets from 1Password provider
	t.Logf("\n=== Fetching secrets with sstart ===")
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	t.Logf("Secrets fetched by sstart:")
	for key, value := range collectedSecrets {
		t.Logf("  - %s: %s", key, value)
	}

	// Verify we got the expected secret
	// When fetching a specific field without section prefix, the key should be just the field name
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

	t.Logf("\n✓ Successfully collected secret from 1Password provider (section field, no section prefix)")
}

package end2end

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dirathea/sstart/internal/config"
	_ "github.com/dirathea/sstart/internal/provider/gcsm"
	"github.com/dirathea/sstart/internal/secrets"
)

// TestE2E_GCSM_WithKeys tests the GCSM provider using real Google Cloud Secret Manager API with key mappings
func TestE2E_GCSM_WithKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires real Google Cloud Secret Manager service")
	}
	ctx := context.Background()

	// Setup GCSM client (uses real API, requires credentials)
	gcsmContainer := SetupGCSM(ctx, t)
	defer func() {
		if err := gcsmContainer.Cleanup(); err != nil {
			t.Errorf("Failed to cleanup GCSM client: %v", err)
		}
	}()

	// Use predefined secret name (must be created beforehand)
	// Can be overridden with GCSM_TEST_SECRET_ID environment variable
	projectID := gcsmContainer.ProjectID
	secretID := os.Getenv("GCSM_TEST_SECRET_ID")
	if secretID == "" {
		secretID = "test-ci"
	}

	// Verify the secret exists (test will skip if it doesn't)
	VerifyGCSMSecretExists(ctx, t, gcsmContainer, projectID, secretID)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	// For real API, don't specify endpoint (uses default)
	configYAML := fmt.Sprintf(`
providers:
  - kind: gcloud_secretmanager
    id: gcsm-test
    project_id: %s
    secret_id: %s
    keys:
      foo: FOO
`, projectID, secretID)

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

	// Collect secrets from GCSM provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify GCSM secrets
	// Note: These values must match what's in the predefined secret
	// The secret test-ci contains: {"foo":"bar"}
	expectedGCSMSecrets := map[string]string{
		"FOO": "bar", // The secret contains {"foo":"bar"}
	}

	for key, expectedValue := range expectedGCSMSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from GCSM not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from GCSM: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedGCSMSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from GCSM provider", len(collectedSecrets))
}

// TestE2E_GCSM_NoKeys tests the GCSM provider using real Google Cloud Secret Manager API without key mappings
func TestE2E_GCSM_NoKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires real Google Cloud Secret Manager service")
	}
	ctx := context.Background()

	// Setup GCSM client (uses real API, requires credentials)
	gcsmContainer := SetupGCSM(ctx, t)
	defer func() {
		if err := gcsmContainer.Cleanup(); err != nil {
			t.Errorf("Failed to cleanup GCSM client: %v", err)
		}
	}()

	// Use predefined secret name (must be created beforehand)
	// Can be overridden with GCSM_TEST_SECRET_ID environment variable
	projectID := gcsmContainer.ProjectID
	secretID := os.Getenv("GCSM_TEST_SECRET_ID")
	if secretID == "" {
		secretID = "test-ci"
	}

	// Verify the secret exists (test will skip if it doesn't)
	VerifyGCSMSecretExists(ctx, t, gcsmContainer, projectID, secretID)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	// For real API, don't specify endpoint (uses default)
	// No keys specified - should collect all keys with original names
	configYAML := fmt.Sprintf(`
providers:
  - kind: gcloud_secretmanager
    id: gcsm-test
    project_id: %s
    secret_id: %s
`, projectID, secretID)

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

	// Collect secrets from GCSM provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify GCSM secrets (should use original key names from secret)
	// The secret test-ci contains: {"foo":"bar"}
	expectedGCSMSecrets := map[string]string{
		"foo": "bar", // Original key name when no mapping is specified
	}

	for key, expectedValue := range expectedGCSMSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from GCSM not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from GCSM: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedGCSMSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from GCSM provider without key mappings", len(collectedSecrets))
}

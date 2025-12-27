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

// Tests for bitwarden_sm (Bitwarden Secret Manager using SDK)
// These tests require a real Bitwarden instance and the following environment variables:
// - SSTART_E2E_BITWARDEN_ORGANIZATION_ID: Organization ID in Bitwarden
// - BITWARDEN_SM_ACCESS_TOKEN: Access token for authentication (same as used by the provider)
// - BITWARDEN_SERVER_URL: (optional) Bitwarden server URL, defaults to https://vault.bitwarden.com (same as used by the provider)
//
// Note: The test will create a new project and secret, then verify that secrets can be fetched from it.
// The project and secret will be cleaned up after the test completes.

// TestE2E_BitwardenSM tests the Bitwarden Secret Manager provider
func TestE2E_BitwardenSM(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires real Bitwarden Secret Manager service")
	}
	ctx := context.Background()

	// Get server URL from environment or use default
	serverURL := os.Getenv("BITWARDEN_SERVER_URL")
	if serverURL == "" {
		serverURL = "https://vault.bitwarden.com"
	}

	// Set up Bitwarden Secret Manager project and secret
	testSetup := SetupBitwardenSMProject(ctx, t, "sstart-test-project", "TEST_SECRET_KEY", "test-secret-value-123")
	defer func() {
		if err := testSetup.Cleanup(); err != nil {
			t.Logf("Warning: Failed to cleanup Bitwarden test resources: %v", err)
		}
	}()

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	// Set environment variables for authentication
	os.Setenv("BITWARDEN_SERVER_URL", serverURL)
	os.Setenv("BITWARDEN_SM_ACCESS_TOKEN", os.Getenv("BITWARDEN_SM_ACCESS_TOKEN"))
	defer func() {
		os.Unsetenv("BITWARDEN_SERVER_URL")
		os.Unsetenv("BITWARDEN_SM_ACCESS_TOKEN")
	}()

	configYAML := fmt.Sprintf(`
providers:
  - kind: bitwarden_sm
    id: bitwarden-sm-test
    server_url: %s
    organization_id: %s
    project_id: %s
`, serverURL, testSetup.OrganizationID, testSetup.ProjectID)

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

	// Verify that at least one secret was collected
	if len(collectedSecrets) == 0 {
		t.Fatalf("No secrets were collected from Bitwarden project '%s'", testSetup.ProjectID)
	}

	// Verify that the test secret was collected
	if value, exists := collectedSecrets["TEST_SECRET_KEY"]; !exists {
		t.Fatalf("Expected secret 'TEST_SECRET_KEY' was not found in collected secrets")
	} else if value != "test-secret-value-123" {
		t.Fatalf("Expected secret value 'test-secret-value-123', got '%s'", value)
	}

	// Log collected secrets for debugging
	t.Logf("Successfully collected %d secrets from Bitwarden Secret Manager project '%s':", len(collectedSecrets), testSetup.ProjectID)
	for key := range collectedSecrets {
		t.Logf("  - %s", key)
		t.Logf("  - %s", collectedSecrets[key])
	}
}

package end2end

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dirathea/sstart/internal/config"
	_ "github.com/dirathea/sstart/internal/provider/aws"
	_ "github.com/dirathea/sstart/internal/provider/azurekeyvault"
	_ "github.com/dirathea/sstart/internal/provider/dotenv"
	_ "github.com/dirathea/sstart/internal/provider/gcsm"
	_ "github.com/dirathea/sstart/internal/provider/vault"
	"github.com/dirathea/sstart/internal/secrets"
)

// TestE2E_MultiProvider tests multiple providers together
// It sets up localstack for AWS Secrets Manager and Vault containers,
// creates secrets in both, and verifies the end-to-end flow
func TestE2E_MultiProvider(t *testing.T) {
	ctx := context.Background()

	// Setup containers
	localstack, vaultContainer := SetupContainers(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
		if err := vaultContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate vault container: %v", err)
		}
	}()

	// Set up AWS Secrets Manager secret
	secretName := "test/myapp/secrets"
	secretData := map[string]string{
		"API_KEY":     "aws-secret-api-key-12345",
		"DB_PASSWORD": "aws-secret-db-password",
		"JWT_SECRET":  "aws-secret-jwt-token",
	}
	SetupAWSSecret(ctx, t, localstack, secretName, secretData)

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
  - kind: aws_secretsmanager
    id: aws-test
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      API_KEY: AWS_API_KEY
      DB_PASSWORD: AWS_DB_PASSWORD
      JWT_SECRET: ==
  
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
`, secretName, localstack.Endpoint, vaultPath, vaultContainer.Address)

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

	// Collect secrets from all providers
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify AWS Secrets Manager secrets
	expectedAWSSecrets := map[string]string{
		"AWS_API_KEY":     "aws-secret-api-key-12345",
		"AWS_DB_PASSWORD": "aws-secret-db-password",
		"JWT_SECRET":      "aws-secret-jwt-token", // Same name (==)
	}

	for key, expectedValue := range expectedAWSSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from AWS Secrets Manager not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from AWS: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
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
	expectedCount := len(expectedAWSSecrets) + len(expectedVaultSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from both providers", len(collectedSecrets))
}

// TestE2E_MultiProvider_Selective tests collecting secrets from specific providers
func TestE2E_MultiProvider_Selective(t *testing.T) {
	ctx := context.Background()

	// Setup containers
	localstack, vaultContainer := SetupContainers(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
		if err := vaultContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate vault container: %v", err)
		}
	}()

	// Set up AWS secret
	secretName := "test/selective"
	secretData := map[string]string{
		"SELECTIVE_KEY": "aws-selective-value",
	}
	SetupAWSSecret(ctx, t, localstack, secretName, secretData)

	// Set up Vault secret
	vaultPath := "selective/config"
	SetupVaultSecret(ctx, t, vaultContainer, vaultPath, map[string]interface{}{
		"VAULT_SELECTIVE_KEY": "vault-selective-value",
	})

	// Create config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: aws-selective
    secret_id: %s
    region: us-east-1
    endpoint: %s
  
  - kind: vault
    id: vault-selective
    path: %s
    address: %s
    token: test-token
    mount: secret
`, secretName, localstack.Endpoint, vaultPath, vaultContainer.Address)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	collector := secrets.NewCollector(cfg)

	// Test collecting only from AWS
	awsSecrets, err := collector.Collect(ctx, []string{"aws-selective"})
	if err != nil {
		t.Fatalf("Failed to collect secrets from AWS: %v", err)
	}

	if len(awsSecrets) != 1 {
		t.Errorf("Expected 1 secret from AWS, got %d", len(awsSecrets))
	}
	if awsSecrets["SELECTIVE_KEY"] != "aws-selective-value" {
		t.Errorf("Expected SELECTIVE_KEY='aws-selective-value', got '%s'", awsSecrets["SELECTIVE_KEY"])
	}

	// Test collecting only from Vault
	vaultSecrets, err := collector.Collect(ctx, []string{"vault-selective"})
	if err != nil {
		t.Fatalf("Failed to collect secrets from Vault: %v", err)
	}

	if len(vaultSecrets) != 1 {
		t.Errorf("Expected 1 secret from Vault, got %d", len(vaultSecrets))
	}
	if vaultSecrets["VAULT_SELECTIVE_KEY"] != "vault-selective-value" {
		t.Errorf("Expected VAULT_SELECTIVE_KEY='vault-selective-value', got '%s'", vaultSecrets["VAULT_SELECTIVE_KEY"])
	}

	t.Logf("Successfully tested selective provider collection")
}

// TestE2E_MultiProvider_All tests all providers together including GCSM
func TestE2E_MultiProvider_All(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires real Google Cloud Secret Manager service")
	}
	ctx := context.Background()

	// Setup containers
	localstack, vaultContainer, gcsmContainer := SetupAllContainers(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
		if err := vaultContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate vault container: %v", err)
		}
		if err := gcsmContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate GCSM container: %v", err)
		}
	}()

	// Set up AWS Secrets Manager secret
	secretName := "test/myapp/secrets"
	secretData := map[string]string{
		"API_KEY":     "aws-secret-api-key-12345",
		"DB_PASSWORD": "aws-secret-db-password",
	}
	SetupAWSSecret(ctx, t, localstack, secretName, secretData)

	// Write secret to Vault
	vaultPath := "myapp/config"
	vaultSecretData := map[string]interface{}{
		"VAULT_API_KEY":     "vault-secret-api-key-67890",
		"VAULT_DB_PASSWORD": "vault-secret-db-password",
	}
	SetupVaultSecret(ctx, t, vaultContainer, vaultPath, vaultSecretData)

	// Use predefined secret name (must be created beforehand)
	// Can be overridden with GCSM_TEST_SECRET_ID environment variable
	projectID := gcsmContainer.ProjectID
	gcsmSecretID := os.Getenv("GCSM_TEST_SECRET_ID")
	if gcsmSecretID == "" {
		gcsmSecretID = "test-ci"
	}

	// Verify the secret exists (test will skip if it doesn't)
	VerifyGCSMSecretExists(ctx, t, gcsmContainer, projectID, gcsmSecretID)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: aws-test
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      API_KEY: AWS_API_KEY
      DB_PASSWORD: AWS_DB_PASSWORD
  
  - kind: vault
    id: vault-test
    path: %s
    address: %s
    token: test-token
    mount: secret
    keys:
      VAULT_API_KEY: VAULT_API_KEY
      VAULT_DB_PASSWORD: VAULT_DB_PASSWORD
  
  - kind: gcloud_secretmanager
    id: gcsm-test
    project_id: %s
    secret_id: %s
    keys:
      foo: FOO
`, secretName, localstack.Endpoint, vaultPath, vaultContainer.Address, projectID, gcsmSecretID)

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

	// Collect secrets from all providers
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify AWS Secrets Manager secrets
	expectedAWSSecrets := map[string]string{
		"AWS_API_KEY":     "aws-secret-api-key-12345",
		"AWS_DB_PASSWORD": "aws-secret-db-password",
	}

	for key, expectedValue := range expectedAWSSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from AWS Secrets Manager not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from AWS: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify Vault secrets
	expectedVaultSecrets := map[string]string{
		"VAULT_API_KEY":     "vault-secret-api-key-67890",
		"VAULT_DB_PASSWORD": "vault-secret-db-password",
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
	expectedCount := len(expectedAWSSecrets) + len(expectedVaultSecrets) + len(expectedGCSMSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from all providers (AWS, Vault, GCSM)", len(collectedSecrets))
}

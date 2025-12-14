package end2end

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dirathea/sstart/internal/config"
	_ "github.com/dirathea/sstart/internal/provider/aws"
	"github.com/dirathea/sstart/internal/secrets"
)

// TestE2E_AWSSecretsManager_WithKeys tests the AWS Secrets Manager provider with key mappings
func TestE2E_AWSSecretsManager_WithKeys(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
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
`, secretName, localstack.Endpoint)

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

	// Collect secrets from AWS Secrets Manager provider
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

	// Verify that we have all expected secrets
	expectedCount := len(expectedAWSSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from AWS Secrets Manager provider", len(collectedSecrets))
}

// TestE2E_AWSSecretsManager_NoKeys tests the AWS Secrets Manager provider without key mappings
func TestE2E_AWSSecretsManager_NoKeys(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	// Set up AWS Secrets Manager secret
	secretName := "test/myapp/no-keys"
	secretData := map[string]string{
		"API_KEY":     "aws-secret-api-key-12345",
		"DB_PASSWORD": "aws-secret-db-password",
		"JWT_SECRET":  "aws-secret-jwt-token",
	}
	SetupAWSSecret(ctx, t, localstack, secretName, secretData)

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
`, secretName, localstack.Endpoint)

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

	// Collect secrets from AWS Secrets Manager provider
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify AWS Secrets Manager secrets (should use original key names)
	expectedAWSSecrets := map[string]string{
		"API_KEY":     "aws-secret-api-key-12345",
		"DB_PASSWORD": "aws-secret-db-password",
		"JWT_SECRET":  "aws-secret-jwt-token",
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

	// Verify that we have all expected secrets
	expectedCount := len(expectedAWSSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from AWS Secrets Manager provider without key mappings", len(collectedSecrets))
}

package end2end

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dirathea/sstart/internal/config"
	_ "github.com/dirathea/sstart/internal/provider/aws"
	"github.com/dirathea/sstart/internal/secrets"
)

// TestE2E_AWS_WithSSOJWT tests AWS Secrets Manager with SSO JWT authentication using LocalStack
func TestE2E_AWS_WithSSOJWT(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	// Create AWS secret in LocalStack
	secretName := "prod/myapp/sso-config"
	secretData := map[string]string{
		"SSO_API_KEY":     "sso-aws-api-key-12345",
		"SSO_DB_PASSWORD": "sso-aws-db-password",
		"SSO_CONFIG":      "sso-config-value",
	}
	SetupAWSSecret(ctx, t, localstack, secretName, secretData)

	// Generate RSA key pair for JWT signing (same as Vault SSO test)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Generate a test JWT token
	jwtToken := generateTestJWT(t, privateKey, "test-user", time.Hour)

	// Setup IAM role in LocalStack for SSO JWT authentication
	roleName := "sstart-test-role"
	roleArn := fmt.Sprintf("arn:aws:iam::000000000000:role/%s", roleName)
	SetupAWSIAMRoleForJWT(ctx, t, localstack, roleName)

	// Create test config with SSO JWT authentication
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: aws-sso-test
    secret_id: %s
    region: us-east-1
    endpoint: %s
    role_arn: %s
    session_name: sstart-test-session
    duration: 3600
    keys:
      SSO_API_KEY: ==
      SSO_DB_PASSWORD: ==
      SSO_CONFIG: ==
`, secretName, localstack.Endpoint, roleArn)

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

	// Inject SSO token manually for testing (similar to Vault SSO test)
	// In real usage, this is done by the SSO authentication flow
	for i := range cfg.Providers {
		cfg.Providers[i].Config["_sso_id_token"] = jwtToken
	}

	// Collect secrets from AWS Secrets Manager with SSO JWT auth
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify secrets
	expectedSecrets := map[string]string{
		"SSO_API_KEY":     "sso-aws-api-key-12345",
		"SSO_DB_PASSWORD": "sso-aws-db-password",
		"SSO_CONFIG":      "sso-config-value",
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s': expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	if len(collectedSecrets) != len(expectedSecrets) {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", len(expectedSecrets), len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets with SSO JWT authentication", len(collectedSecrets))
}

// TestE2E_AWS_WithoutSSO tests that AWS provider works without SSO (backward compatibility)
func TestE2E_AWS_WithoutSSO(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	// Create AWS secret in LocalStack
	secretName := "test/myapp/no-sso"
	secretData := map[string]string{
		"API_KEY":     "regular-api-key",
		"DB_PASSWORD": "regular-db-password",
	}
	SetupAWSSecret(ctx, t, localstack, secretName, secretData)

	// Create test config WITHOUT SSO (existing behavior should still work)
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: aws-no-sso
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      API_KEY: ==
      DB_PASSWORD: ==
`, secretName, localstack.Endpoint)

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

	// Collect secrets WITHOUT SSO (should use default AWS credentials)
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify secrets
	expectedSecrets := map[string]string{
		"API_KEY":     "regular-api-key",
		"DB_PASSWORD": "regular-db-password",
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s': expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	t.Logf("Successfully collected %d secrets WITHOUT SSO (backward compatibility test)", len(collectedSecrets))
}

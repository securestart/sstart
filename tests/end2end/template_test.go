package end2end

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dirathea/sstart/internal/config"
	_ "github.com/dirathea/sstart/internal/provider/aws"
	_ "github.com/dirathea/sstart/internal/provider/template"
	"github.com/dirathea/sstart/internal/secrets"
)

// TestE2E_TemplateProvider tests the template provider functionality
// It sets up multiple AWS Secrets Manager secrets and uses a template provider
// to construct a new secret from them
func TestE2E_TemplateProvider(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	// Set up first AWS secret with PG_HOST
	secretName1 := "test/template/host"
	secretData1 := map[string]string{
		"PG_HOST": "db.example.com",
	}
	SetupAWSSecret(ctx, t, localstack, secretName1, secretData1)

	// Set up second AWS secret with PG_USERNAME and PG_PASSWORD
	secretName2 := "test/template/credentials"
	secretData2 := map[string]string{
		"PG_USERNAME": "myuser",
		"PG_PASSWORD": "mypassword",
	}
	SetupAWSSecret(ctx, t, localstack, secretName2, secretData2)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: aws_generic
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      PG_HOST: PG_HOST
  
  - kind: aws_secretsmanager
    id: aws_prod
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      PG_USERNAME: PG_USERNAME
      PG_PASSWORD: PG_PASSWORD
  
  - kind: template
    uses:
      - aws_prod
      - aws_generic
    templates:
      PG_URI: pgsql://{{.aws_prod.PG_USERNAME}}:{{.aws_prod.PG_PASSWORD}}@{{.aws_generic.PG_HOST}}
`, secretName1, localstack.Endpoint, secretName2, localstack.Endpoint)

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

	// Verify original secrets are present
	expectedSecrets := map[string]string{
		"PG_HOST":     "db.example.com",
		"PG_USERNAME": "myuser",
		"PG_PASSWORD": "mypassword",
		"PG_URI":      "pgsql://myuser:mypassword@db.example.com",
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

	t.Logf("Successfully tested template provider with %d secrets", len(collectedSecrets))
}

// TestE2E_TemplateProvider_Complex tests a more complex template with multiple references
func TestE2E_TemplateProvider_Complex(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	// Set up AWS secrets
	secretName1 := "test/template/api"
	secretData1 := map[string]string{
		"API_KEY":    "secret-api-key-123",
		"API_SECRET": "secret-api-secret-456",
	}
	SetupAWSSecret(ctx, t, localstack, secretName1, secretData1)

	secretName2 := "test/template/db"
	secretData2 := map[string]string{
		"DB_HOST": "localhost",
		"DB_PORT": "5432",
	}
	SetupAWSSecret(ctx, t, localstack, secretName2, secretData2)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: api_secrets
    secret_id: %s
    region: us-east-1
    endpoint: %s
  
  - kind: aws_secretsmanager
    id: db_config
    secret_id: %s
    region: us-east-1
    endpoint: %s
  
  - kind: template
    uses:
      - api_secrets
      - db_config
    templates:
      API_CONFIG: api_key={{.api_secrets.API_KEY}}&api_secret={{.api_secrets.API_SECRET}}
      DB_URL: postgresql://{{.db_config.DB_HOST}}:{{.db_config.DB_PORT}}/mydb
`, secretName1, localstack.Endpoint, secretName2, localstack.Endpoint)

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

	// Verify template secrets
	expectedAPIConfig := "api_key=secret-api-key-123&api_secret=secret-api-secret-456"
	expectedDBURL := "postgresql://localhost:5432/mydb"

	if collectedSecrets["API_CONFIG"] != expectedAPIConfig {
		t.Errorf("API_CONFIG: expected '%s', got '%s'", expectedAPIConfig, collectedSecrets["API_CONFIG"])
	}

	if collectedSecrets["DB_URL"] != expectedDBURL {
		t.Errorf("DB_URL: expected '%s', got '%s'", expectedDBURL, collectedSecrets["DB_URL"])
	}

	t.Logf("Successfully tested complex template provider")
}

// TestE2E_TemplateProvider_EndToEnd tests template provider with actual command execution
func TestE2E_TemplateProvider_EndToEnd(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	// Set up AWS secrets
	secretName1 := "test/template/e2e/host"
	secretData1 := map[string]string{
		"PG_HOST": "production.db.example.com",
	}
	SetupAWSSecret(ctx, t, localstack, secretName1, secretData1)

	secretName2 := "test/template/e2e/creds"
	secretData2 := map[string]string{
		"PG_USERNAME": "produser",
		"PG_PASSWORD": "prodpass123",
	}
	SetupAWSSecret(ctx, t, localstack, secretName2, secretData2)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: aws_generic
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      PG_HOST: PG_HOST
  
  - kind: aws_secretsmanager
    id: aws_prod
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      PG_USERNAME: PG_USERNAME
      PG_PASSWORD: PG_PASSWORD
  
  - kind: template
    uses:
      - aws_prod
      - aws_generic
    templates:
      PG_URI: pgsql://{{.aws_prod.PG_USERNAME}}:{{.aws_prod.PG_PASSWORD}}@{{.aws_generic.PG_HOST}}
`, secretName1, localstack.Endpoint, secretName2, localstack.Endpoint)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create a test script that verifies the template secret
	testScript := filepath.Join(tmpDir, "test_template.sh")
	scriptContent := `#!/bin/sh
# Verify template-generated secret
if [ "$PG_URI" != "pgsql://produser:prodpass123@production.db.example.com" ]; then
  echo "ERROR: PG_URI mismatch. Expected: pgsql://produser:prodpass123@production.db.example.com, Got: $PG_URI"
  exit 1
fi

# Verify original secrets are also present
if [ "$PG_HOST" != "production.db.example.com" ]; then
  echo "ERROR: PG_HOST mismatch. Expected: production.db.example.com, Got: $PG_HOST"
  exit 1
fi

if [ "$PG_USERNAME" != "produser" ]; then
  echo "ERROR: PG_USERNAME mismatch. Expected: produser, Got: $PG_USERNAME"
  exit 1
fi

if [ "$PG_PASSWORD" != "prodpass123" ]; then
  echo "ERROR: PG_PASSWORD mismatch. Expected: prodpass123, Got: $PG_PASSWORD"
  exit 1
fi

echo "SUCCESS: Template provider works correctly"
exit 0
`

	if err := os.WriteFile(testScript, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("Failed to write test script: %v", err)
	}

	// Build sstart binary
	sstartBinary := filepath.Join(tmpDir, "sstart")
	projectRoot := getProjectRoot(t)
	cmdPath := filepath.Join(projectRoot, "cmd", "sstart")
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", sstartBinary, cmdPath)
	buildCmd.Dir = projectRoot
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build sstart binary: %v", err)
	}

	// Run sstart with the test script
	runCmd := exec.CommandContext(ctx, sstartBinary, "--config", configFile, "run", "--", testScript)
	runCmd.Dir = tmpDir
	output, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run sstart command: %v\nOutput: %s", err, output)
	}

	if !strings.Contains(string(output), "SUCCESS") {
		t.Errorf("Test script failed. Output: %s", output)
	}
}

// TestE2E_TemplateProvider_ErrorHandling tests error handling for missing references
func TestE2E_TemplateProvider_ErrorHandling(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	// Set up AWS secret
	secretName := "test/template/error"
	secretData := map[string]string{
		"EXISTING_KEY": "existing-value",
	}
	SetupAWSSecret(ctx, t, localstack, secretName, secretData)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	// Build sstart binary
	sstartBinary := filepath.Join(tmpDir, "sstart")
	projectRoot := getProjectRoot(t)
	cmdPath := filepath.Join(projectRoot, "cmd", "sstart")
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", sstartBinary, cmdPath)
	buildCmd.Dir = projectRoot
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build sstart binary: %v", err)
	}

	// Test case 1: Template provider references non-existent provider
	configYAML1 := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: aws_existing
    secret_id: %s
    region: us-east-1
    endpoint: %s
  
  - kind: template
    uses:
      - nonexistent_provider
    templates:
      TEST_KEY: "{{.nonexistent_provider.SOME_KEY}}"
`, secretName, localstack.Endpoint)

	if err := os.WriteFile(configFile, []byte(configYAML1), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create a test script that verifies the template resolves with empty value for non-existent provider
	testScript := filepath.Join(tmpDir, "test_template.sh")
	scriptContent := `#!/bin/sh
# Verify template resolves to <no value> for non-existent provider
if [ "$TEST_KEY" != "<no value>" ]; then
  echo "ERROR: TEST_KEY mismatch. Expected: '<no value>', Got: '$TEST_KEY'"
  exit 1
fi

echo "SUCCESS: Template provider correctly resolves with empty value for non-existent provider"
exit 0
`

	if err := os.WriteFile(testScript, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("Failed to write test script: %v", err)
	}

	// Run sstart with the test script - should succeed with empty value for non-existent provider
	runCmd := exec.CommandContext(ctx, sstartBinary, "--config", configFile, "run", "--", testScript)
	runCmd.Dir = tmpDir
	output, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run sstart command: %v\nOutput: %s", err, output)
	}

	if !strings.Contains(string(output), "SUCCESS") {
		t.Errorf("Test script failed. Output: %s", output)
	}

	t.Logf("Successfully tested template provider error handling")
}

// TestE2E_TemplateProvider_WithoutUses tests that template provider cannot access secrets when 'uses' is not specified
func TestE2E_TemplateProvider_WithoutUses(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	// Set up AWS secret
	secretName := "test/template/without-uses"
	secretData := map[string]string{
		"SECRET_KEY": "secret-value",
	}
	SetupAWSSecret(ctx, t, localstack, secretName, secretData)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	// Template provider without 'uses' should resolve to empty value when accessing other providers' secrets
	configYAML := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: aws_secret
    secret_id: %s
    region: us-east-1
    endpoint: %s
  
  - kind: template
    templates:
      TEST_KEY: "{{.aws_secret.SECRET_KEY}}"
`, secretName, localstack.Endpoint)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Build sstart binary
	sstartBinary := filepath.Join(tmpDir, "sstart")
	projectRoot := getProjectRoot(t)
	cmdPath := filepath.Join(projectRoot, "cmd", "sstart")
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", sstartBinary, cmdPath)
	buildCmd.Dir = projectRoot
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build sstart binary: %v", err)
	}

	// Create a test script that verifies the template resolves with empty value when 'uses' is not specified
	testScript := filepath.Join(tmpDir, "test_template.sh")
	scriptContent := `#!/bin/sh
# Verify template resolves to <no value> when 'uses' is not specified
if [ "$TEST_KEY" != "<no value>" ]; then
  echo "ERROR: TEST_KEY mismatch. Expected: '<no value>', Got: '$TEST_KEY'"
  exit 1
fi

echo "SUCCESS: Template provider correctly resolves with empty value when 'uses' is not specified"
exit 0
`

	if err := os.WriteFile(testScript, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("Failed to write test script: %v", err)
	}

	// Run sstart with the test script - should succeed with empty value when 'uses' is not specified
	runCmd := exec.CommandContext(ctx, sstartBinary, "--config", configFile, "run", "--", testScript)
	runCmd.Dir = tmpDir
	output, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run sstart command: %v\nOutput: %s", err, output)
	}

	if !strings.Contains(string(output), "SUCCESS") {
		t.Errorf("Test script failed. Output: %s", output)
	}

	t.Logf("Successfully tested template provider security: cannot access secrets without 'uses'")
}

// TestE2E_TemplateProvider_UsesNotInList tests that template provider cannot access providers not in 'uses' list
func TestE2E_TemplateProvider_UsesNotInList(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	// Set up two AWS secrets
	secretName1 := "test/template/uses1"
	secretData1 := map[string]string{
		"KEY1": "value1",
	}
	SetupAWSSecret(ctx, t, localstack, secretName1, secretData1)

	secretName2 := "test/template/uses2"
	secretData2 := map[string]string{
		"KEY2": "value2",
	}
	SetupAWSSecret(ctx, t, localstack, secretName2, secretData2)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	// Template provider with 'uses' that only includes aws_secret1, but tries to access aws_secret2
	configYAML := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: aws_secret1
    secret_id: %s
    region: us-east-1
    endpoint: %s
  
  - kind: aws_secretsmanager
    id: aws_secret2
    secret_id: %s
    region: us-east-1
    endpoint: %s
  
  - kind: template
    uses:
      - aws_secret1
    templates:
      TEST_KEY: "{{.aws_secret1.KEY1}} and {{.aws_secret2.KEY2}}"
`, secretName1, localstack.Endpoint, secretName2, localstack.Endpoint)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Build sstart binary
	sstartBinary := filepath.Join(tmpDir, "sstart")
	projectRoot := getProjectRoot(t)
	cmdPath := filepath.Join(projectRoot, "cmd", "sstart")
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", sstartBinary, cmdPath)
	buildCmd.Dir = projectRoot
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build sstart binary: %v", err)
	}

	// Create a test script that verifies the template resolves with empty value for provider not in 'uses'
	testScript := filepath.Join(tmpDir, "test_template.sh")
	scriptContent := `#!/bin/sh
# Verify template resolves: aws_secret1.KEY1 should be "value1", aws_secret2.KEY2 should be empty (<no value>)
if [ "$TEST_KEY" != "value1 and <no value>" ]; then
  echo "ERROR: TEST_KEY mismatch. Expected: 'value1 and <no value>', Got: '$TEST_KEY'"
  exit 1
fi

echo "SUCCESS: Template provider correctly resolves with empty value for provider not in 'uses' list"
exit 0
`

	if err := os.WriteFile(testScript, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("Failed to write test script: %v", err)
	}

	// Run sstart with the test script - should succeed with empty value for provider not in 'uses'
	runCmd := exec.CommandContext(ctx, sstartBinary, "--config", configFile, "run", "--", testScript)
	runCmd.Dir = tmpDir
	output, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run sstart command: %v\nOutput: %s", err, output)
	}

	if !strings.Contains(string(output), "SUCCESS") {
		t.Errorf("Test script failed. Output: %s", output)
	}

	t.Logf("Successfully tested template provider: providers not in 'uses' list resolve to empty values")
}

package end2end

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// TestE2E_Format_ValidJSON tests that valid JSON secrets are parsed correctly
func TestE2E_Format_ValidJSON(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	// Set up AWS secret with valid JSON
	secretName := "test/format/valid-json"
	secretData := map[string]string{
		"API_KEY":     "valid-api-key-123",
		"DB_PASSWORD": "valid-db-password",
		"JWT_SECRET":  "valid-jwt-secret",
	}
	SetupAWSSecret(ctx, t, localstack, secretName, secretData)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: aws-valid-json
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      API_KEY: API_KEY
      DB_PASSWORD: DB_PASSWORD
      JWT_SECRET: JWT_SECRET
`, secretName, localstack.Endpoint)

	if err := os.WriteFile(configFile, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create a test script that verifies JSON secrets are parsed correctly
	testScript := filepath.Join(tmpDir, "test_valid_json.sh")
	scriptContent := `#!/bin/sh
# Verify all JSON secrets are accessible with correct values
if [ "$API_KEY" != "valid-api-key-123" ]; then
  echo "ERROR: API_KEY mismatch. Expected: valid-api-key-123, Got: $API_KEY"
  exit 1
fi

if [ "$DB_PASSWORD" != "valid-db-password" ]; then
  echo "ERROR: DB_PASSWORD mismatch. Expected: valid-db-password, Got: $DB_PASSWORD"
  exit 1
fi

if [ "$JWT_SECRET" != "valid-jwt-secret" ]; then
  echo "ERROR: JWT_SECRET mismatch. Expected: valid-jwt-secret, Got: $JWT_SECRET"
  exit 1
fi

echo "SUCCESS: All JSON secrets parsed correctly"
exit 0
`

	if err := os.WriteFile(testScript, []byte(scriptContent), 0o755); err != nil {
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

// TestE2E_Format_MultipleSecretsOverride tests that later providers override earlier ones
func TestE2E_Format_MultipleSecretsOverride(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	// Set up first AWS secret
	secretName1 := "test/format/secret1"
	secretData1 := map[string]string{
		"SHARED_KEY": "first-secret-value",
		"KEY1_ONLY":  "key1-only-value",
	}
	SetupAWSSecret(ctx, t, localstack, secretName1, secretData1)

	// Set up second AWS secret (will override SHARED_KEY)
	secretName2 := "test/format/secret2"
	secretData2 := map[string]string{
		"SHARED_KEY": "second-secret-value-override",
		"KEY2_ONLY":  "key2-only-value",
	}
	SetupAWSSecret(ctx, t, localstack, secretName2, secretData2)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: aws-override-1
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      SHARED_KEY: SHARED_KEY
      KEY1_ONLY: KEY1_ONLY
  
  - kind: aws_secretsmanager
    id: aws-override-2
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      SHARED_KEY: SHARED_KEY
      KEY2_ONLY: KEY2_ONLY
`, secretName1, localstack.Endpoint, secretName2, localstack.Endpoint)

	if err := os.WriteFile(configFile, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create a test script that verifies override behavior
	testScript := filepath.Join(tmpDir, "test_override.sh")
	scriptContent := `#!/bin/sh
# Verify SHARED_KEY is overridden by second provider
if [ "$SHARED_KEY" != "second-secret-value-override" ]; then
  echo "ERROR: SHARED_KEY should be overridden. Expected: second-secret-value-override, Got: $SHARED_KEY"
  exit 1
fi

# Verify KEY1_ONLY is still present
if [ "$KEY1_ONLY" != "key1-only-value" ]; then
  echo "ERROR: KEY1_ONLY mismatch. Expected: key1-only-value, Got: $KEY1_ONLY"
  exit 1
fi

# Verify KEY2_ONLY is present
if [ "$KEY2_ONLY" != "key2-only-value" ]; then
  echo "ERROR: KEY2_ONLY mismatch. Expected: key2-only-value, Got: $KEY2_ONLY"
  exit 1
fi

echo "SUCCESS: Multiple secrets override correctly"
exit 0
`

	if err := os.WriteFile(testScript, []byte(scriptContent), 0o755); err != nil {
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

// TestE2E_Format_NonJSONSecret tests that non-JSON secrets are loaded to <PROVIDER_ID>_SECRET
func TestE2E_Format_NonJSONSecret(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	// Set up AWS secret with plain text (non-JSON)
	secretName := "test/format/non-json"
	plainTextSecret := "this-is-a-plain-text-secret-value-12345"

	awsRegion := "us-east-1"
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(awsRegion),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	secretsManagerClient := secretsmanager.NewFromConfig(awsCfg, func(o *secretsmanager.Options) {
		o.BaseEndpoint = aws.String(localstack.Endpoint)
	})

	_, err = secretsManagerClient.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(secretName),
		SecretString: aws.String(plainTextSecret), // Plain text, not JSON
	})
	if err != nil {
		t.Fatalf("Failed to create secret in AWS Secrets Manager: %v", err)
	}

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: aws-non-json
    secret_id: %s
    region: us-east-1
    endpoint: %s
`, secretName, localstack.Endpoint)

	if err := os.WriteFile(configFile, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create a test script that verifies non-JSON secret is loaded correctly
	testScript := filepath.Join(tmpDir, "test_non_json.sh")
	scriptContent := `#!/bin/sh
# Verify non-JSON secret is loaded to <PROVIDER_ID>_SECRET (uppercase)
if [ "$AWS_NON_JSON_SECRET" != "this-is-a-plain-text-secret-value-12345" ]; then
  echo "ERROR: AWS_NON_JSON_SECRET mismatch. Expected: this-is-a-plain-text-secret-value-12345, Got: $AWS_NON_JSON_SECRET"
  exit 1
fi

echo "SUCCESS: Non-JSON secret loaded correctly to AWS_NON_JSON_SECRET"
exit 0
`

	if err := os.WriteFile(testScript, []byte(scriptContent), 0o755); err != nil {
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

	// Run sstart with the test script and capture stderr to check for warning
	runCmd := exec.CommandContext(ctx, sstartBinary, "--config", configFile, "run", "--", testScript)
	runCmd.Dir = tmpDir
	output, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run sstart command: %v\nOutput: %s", err, output)
	}

	// Verify the warning message is present in the output
	outputStr := string(output)
	if !strings.Contains(outputStr, "WARN") || !strings.Contains(outputStr, "not JSON format") {
		t.Errorf("Warning message not found in output. Expected WARN about non-JSON format. Output: %s", outputStr)
	}

	if !strings.Contains(outputStr, "aws-non-json") {
		t.Errorf("Warning should mention provider ID 'aws-non-json'. Output: %s", outputStr)
	}

	if !strings.Contains(outputStr, "AWS_NON_JSON_SECRET") {
		t.Errorf("Warning should mention the environment variable name 'AWS_NON_JSON_SECRET'. Output: %s", outputStr)
	}

	if !strings.Contains(outputStr, "SUCCESS") {
		t.Errorf("Test script failed. Output: %s", outputStr)
	}
}

// TestE2E_Format_MixedJSONAndNonJSON tests a combination of JSON and non-JSON secrets
func TestE2E_Format_MixedJSONAndNonJSON(t *testing.T) {
	ctx := context.Background()

	// Setup LocalStack container
	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	// Set up AWS secret with valid JSON
	jsonSecretName := "test/format/mixed-json"
	jsonSecretData := map[string]string{
		"JSON_API_KEY": "json-api-key-value",
		"JSON_DB_PASS": "json-db-password",
	}
	SetupAWSSecret(ctx, t, localstack, jsonSecretName, jsonSecretData)

	// Set up AWS secret with plain text (non-JSON)
	nonJSONSecretName := "test/format/mixed-non-json"
	plainTextSecret := "plain-text-secret-content"

	awsRegion := "us-east-1"
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(awsRegion),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	secretsManagerClient := secretsmanager.NewFromConfig(awsCfg, func(o *secretsmanager.Options) {
		o.BaseEndpoint = aws.String(localstack.Endpoint)
	})

	_, err = secretsManagerClient.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(nonJSONSecretName),
		SecretString: aws.String(plainTextSecret), // Plain text, not JSON
	})
	if err != nil {
		t.Fatalf("Failed to create non-JSON secret in AWS Secrets Manager: %v", err)
	}

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: aws-json-mixed
    secret_id: %s
    region: us-east-1
    endpoint: %s
    keys:
      JSON_API_KEY: JSON_API_KEY
      JSON_DB_PASS: JSON_DB_PASS
  
  - kind: aws_secretsmanager
    id: aws-nonjson-mixed
    secret_id: %s
    region: us-east-1
    endpoint: %s
`, jsonSecretName, localstack.Endpoint, nonJSONSecretName, localstack.Endpoint)

	if err := os.WriteFile(configFile, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create a test script that verifies both JSON and non-JSON secrets
	testScript := filepath.Join(tmpDir, "test_mixed.sh")
	scriptContent := `#!/bin/sh
# Verify JSON secrets are parsed correctly
if [ "$JSON_API_KEY" != "json-api-key-value" ]; then
  echo "ERROR: JSON_API_KEY mismatch. Expected: json-api-key-value, Got: $JSON_API_KEY"
  exit 1
fi

if [ "$JSON_DB_PASS" != "json-db-password" ]; then
  echo "ERROR: JSON_DB_PASS mismatch. Expected: json-db-password, Got: $JSON_DB_PASS"
  exit 1
fi

# Verify non-JSON secret is loaded to <PROVIDER_ID>_SECRET
if [ "$AWS_NONJSON_MIXED_SECRET" != "plain-text-secret-content" ]; then
  echo "ERROR: AWS_NONJSON_MIXED_SECRET mismatch. Expected: plain-text-secret-content, Got: $AWS_NONJSON_MIXED_SECRET"
  exit 1
fi

echo "SUCCESS: Mixed JSON and non-JSON secrets handled correctly"
exit 0
`

	if err := os.WriteFile(testScript, []byte(scriptContent), 0o755); err != nil {
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

	outputStr := string(output)
	// Verify warning is present for non-JSON secret
	if !strings.Contains(outputStr, "WARN") || !strings.Contains(outputStr, "not JSON format") {
		t.Errorf("Warning message not found for non-JSON secret. Output: %s", outputStr)
	}

	if !strings.Contains(outputStr, "SUCCESS") {
		t.Errorf("Test script failed. Output: %s", outputStr)
	}
}

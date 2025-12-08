package end2end

import (
	"context"
	"os"
	"testing"

	infisical "github.com/infisical/go-sdk"
)

// SetupInfisicalClient creates and authenticates an Infisical client for testing
func SetupInfisicalClient(ctx context.Context, t *testing.T) infisical.InfisicalClientInterface {
	t.Helper()

	// Check for required environment variables
	clientID := os.Getenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID")
	clientSecret := os.Getenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET")

	if clientID == "" || clientSecret == "" {
		t.Skipf("Skipping test: INFISICAL_UNIVERSAL_AUTH_CLIENT_ID and INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET environment variables are required")
	}

	// Get site URL from environment variable (optional, defaults to https://app.infisical.com)
	siteURL := os.Getenv("INFISICAL_SITE_URL")

	// Create client config
	clientConfig := infisical.Config{}
	if siteURL != "" {
		clientConfig.SiteUrl = siteURL
	}

	// Create client
	client := infisical.NewInfisicalClient(ctx, clientConfig)

	// Authenticate using universal auth
	_, err := client.Auth().UniversalAuthLogin(clientID, clientSecret)
	if err != nil {
		t.Fatalf("Failed to authenticate with Infisical: %v", err)
	}

	return client
}

// GetInfisicalTestProjectID returns the test project ID from environment variable
func GetInfisicalTestProjectID(t *testing.T) string {
	t.Helper()

	projectID := os.Getenv("SSTART_E2E_INFISICAL_PROJECT_ID")
	if projectID == "" {
		t.Skipf("Skipping test: SSTART_E2E_INFISICAL_PROJECT_ID environment variable is required")
	}

	return projectID
}

// GetInfisicalTestEnvironment returns the test environment from environment variable
func GetInfisicalTestEnvironment(t *testing.T) string {
	t.Helper()

	environment := os.Getenv("SSTART_E2E_INFISICAL_ENVIRONMENT")
	if environment == "" {
		t.Skipf("Skipping test: SSTART_E2E_INFISICAL_ENVIRONMENT environment variable is required")
	}

	return environment
}

// EnsureInfisicalPathExists ensures that the given path exists in Infisical
// For root path "/", this is a no-op as it always exists
// For other paths, Infisical will automatically create the path structure when secrets are created
func EnsureInfisicalPathExists(ctx context.Context, t *testing.T, client infisical.InfisicalClientInterface, projectID, environment, secretPath string) {
	t.Helper()

	// Root path always exists, no need to check or create
	// Note: Infisical automatically creates folder paths when secrets are created at those paths
}

// SetupInfisicalSecret creates or updates a secret in Infisical for testing
// It ensures the path exists and then creates/updates the secret without listing all secrets first
func SetupInfisicalSecret(ctx context.Context, t *testing.T, client infisical.InfisicalClientInterface, projectID, environment, secretPath, secretKey, secretValue string) {
	t.Helper()

	// Ensure the path exists
	EnsureInfisicalPathExists(ctx, t, client, projectID, environment, secretPath)

	// Try to create the secret first
	createOptions := infisical.CreateSecretOptions{
		SecretKey:   secretKey,
		ProjectID:   projectID,
		Environment: environment,
		SecretPath:  secretPath,
		SecretValue: secretValue,
	}

	_, err := client.Secrets().Create(createOptions)
	if err != nil {
		// If creation fails, it might be because the secret already exists
		// Try to update it instead
		updateOptions := infisical.UpdateSecretOptions{
			SecretKey:   secretKey,
			ProjectID:   projectID,
			Environment: environment,
			SecretPath:  secretPath,
		}
		updateOptions.NewSecretValue = secretValue

		_, err := client.Secrets().Update(updateOptions)
		if err != nil {
			t.Fatalf("Failed to create or update secret in Infisical: %v", err)
		}
	}
}

// SetupInfisicalSecretsBatch creates or updates multiple secrets in Infisical using batch operations
// secrets is a map of secretKey -> secretValue
func SetupInfisicalSecretsBatch(ctx context.Context, t *testing.T, client infisical.InfisicalClientInterface, projectID, environment, secretPath string, secrets map[string]string) {
	t.Helper()

	if len(secrets) == 0 {
		return
	}

	// Ensure the path exists
	EnsureInfisicalPathExists(ctx, t, client, projectID, environment, secretPath)

	// Build batch create secrets array
	batchSecrets := make([]infisical.BatchCreateSecret, 0, len(secrets))
	for secretKey, secretValue := range secrets {
		batchSecrets = append(batchSecrets, infisical.BatchCreateSecret{
			SecretKey:   secretKey,
			SecretValue: secretValue,
		})
	}

	// Create batch options
	batchOptions := infisical.BatchCreateSecretsOptions{
		ProjectID:   projectID,
		Environment: environment,
		SecretPath:  secretPath,
		Secrets:     batchSecrets,
	}

	// Try batch create first
	_, err := client.Secrets().Batch().Create(batchOptions)
	if err != nil {
		// If batch create fails, fall back to individual create/update
		t.Logf("Batch create failed, falling back to individual operations: %v", err)
		for secretKey, secretValue := range secrets {
			SetupInfisicalSecret(ctx, t, client, projectID, environment, secretPath, secretKey, secretValue)
		}
	}
}

// VerifyInfisicalSecretExists checks if a secret exists in Infisical
func VerifyInfisicalSecretExists(ctx context.Context, t *testing.T, client infisical.InfisicalClientInterface, projectID, environment, secretPath, secretKey string) {
	t.Helper()

	listOptions := infisical.ListSecretsOptions{
		ProjectID:   projectID,
		Environment: environment,
		SecretPath:  secretPath,
	}

	secrets, err := client.Secrets().List(listOptions)
	if err != nil {
		t.Fatalf("Failed to list secrets from Infisical: %v", err)
	}

	for _, secret := range secrets {
		if secret.SecretKey == secretKey && secret.SecretPath == secretPath {
			return // Secret exists
		}
	}

	t.Skipf("Skipping test: Secret '%s' does not exist at path '%s' in environment '%s' of project '%s'. "+
		"Please create it beforehand in your Infisical project.", secretKey, secretPath, environment, projectID)
}

// DeleteInfisicalSecret deletes a secret from Infisical (if it exists)
func DeleteInfisicalSecret(ctx context.Context, t *testing.T, client infisical.InfisicalClientInterface, projectID, environment, secretPath, secretKey string) {
	t.Helper()

	// Delete the secret using key, path, project, and environment
	deleteOptions := infisical.DeleteSecretOptions{
		SecretKey:   secretKey,
		ProjectID:   projectID,
		Environment: environment,
		SecretPath:  secretPath,
	}
	_, err := client.Secrets().Delete(deleteOptions)
	if err != nil {
		// Log but don't fail - the secret might not exist, which is fine
		t.Logf("Note: Could not delete secret '%s' from Infisical (may not exist): %v", secretKey, err)
	}
}

// DeleteInfisicalSecretsBatch deletes multiple secrets from Infisical (if they exist)
// secretKeys is a slice of secret keys to delete
func DeleteInfisicalSecretsBatch(ctx context.Context, t *testing.T, client infisical.InfisicalClientInterface, projectID, environment, secretPath string, secretKeys []string) {
	t.Helper()

	if len(secretKeys) == 0 {
		return
	}

	// Delete each secret individually (batch delete not available in SDK)
	// This is still more efficient than calling the function multiple times from tests
	for _, secretKey := range secretKeys {
		DeleteInfisicalSecret(ctx, t, client, projectID, environment, secretPath, secretKey)
	}
}

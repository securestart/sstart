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

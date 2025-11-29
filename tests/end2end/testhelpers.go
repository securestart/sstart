package end2end

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"crypto/tls"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/hashicorp/vault/api"
	"github.com/testcontainers/testcontainers-go"
	localstack "github.com/testcontainers/testcontainers-go/modules/localstack"
	"github.com/testcontainers/testcontainers-go/modules/vault"
	"github.com/testcontainers/testcontainers-go/wait"
)

// LocalStackContainer wraps LocalStack container and its endpoint
type LocalStackContainer struct {
	Container *localstack.LocalStackContainer
	Endpoint  string
	Cleanup   func() error
}

// VaultContainer wraps Vault container, address, and client
type VaultContainer struct {
	Container *vault.VaultContainer
	Address   string
	Client    *api.Client
	Cleanup   func() error
}

// GCSMContainer wraps GCSM client for real API testing
type GCSMContainer struct {
	Container testcontainers.Container // nil for real API
	Endpoint  string                   // empty for real API
	Client    *secretmanager.Client
	ProjectID string // GCP project ID for real API
	Cleanup   func() error
}

// AzureKeyVaultContainer wraps Azure Key Vault emulator container and client
type AzureKeyVaultContainer struct {
	Container testcontainers.Container
	VaultURL  string
	Client    *azsecrets.Client
	Cleanup   func() error
}

// SetupLocalStack starts a LocalStack container and returns the container info
func SetupLocalStack(ctx context.Context, t *testing.T) *LocalStackContainer {
	t.Helper()

	container, err := localstack.Run(ctx, "localstack/localstack:latest")
	if err != nil {
		t.Fatalf("Failed to start localstack container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get localstack host: %v", err)
	}

	port, err := container.MappedPort(ctx, "4566/tcp")
	if err != nil {
		t.Fatalf("Failed to get localstack port: %v", err)
	}

	endpoint := fmt.Sprintf("http://%s:%s", host, port.Port())

	return &LocalStackContainer{
		Container: container,
		Endpoint:  endpoint,
		Cleanup: func() error {
			return container.Terminate(ctx)
		},
	}
}

// SetupVault starts a Vault container and returns the container info
func SetupVault(ctx context.Context, t *testing.T) *VaultContainer {
	t.Helper()

	container, err := vault.Run(ctx, "hashicorp/vault:latest",
		vault.WithToken("test-token"),
	)
	if err != nil {
		t.Fatalf("Failed to start vault container: %v", err)
	}

	address, err := container.HttpHostAddress(ctx)
	if err != nil {
		t.Fatalf("Failed to get vault address: %v", err)
	}

	client, err := api.NewClient(&api.Config{
		Address: address,
	})
	if err != nil {
		t.Fatalf("Failed to create vault client: %v", err)
	}
	client.SetToken("test-token")

	return &VaultContainer{
		Container: container,
		Address:   address,
		Client:    client,
		Cleanup: func() error {
			return container.Terminate(ctx)
		},
	}
}

// SetupContainers sets up both LocalStack and Vault containers
func SetupContainers(ctx context.Context, t *testing.T) (*LocalStackContainer, *VaultContainer) {
	t.Helper()

	localstack := SetupLocalStack(ctx, t)
	vault := SetupVault(ctx, t)

	// Wait for containers to be ready
	time.Sleep(2 * time.Second)

	return localstack, vault
}

// SetupAllContainers sets up LocalStack, Vault, and GCSM containers
func SetupAllContainers(ctx context.Context, t *testing.T) (*LocalStackContainer, *VaultContainer, *GCSMContainer) {
	t.Helper()

	localstack := SetupLocalStack(ctx, t)
	vault := SetupVault(ctx, t)
	gcsm := SetupGCSM(ctx, t)

	// Wait for containers to be ready
	time.Sleep(2 * time.Second)

	return localstack, vault, gcsm
}

// SetupAWSSecret creates a secret in AWS Secrets Manager (LocalStack)
func SetupAWSSecret(ctx context.Context, t *testing.T, localstack *LocalStackContainer, secretName string, secretData map[string]string) {
	t.Helper()

	awsRegion := "us-east-1"
	secretJSON, err := json.Marshal(secretData)
	if err != nil {
		t.Fatalf("Failed to marshal secret data: %v", err)
	}

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
		SecretString: aws.String(string(secretJSON)),
	})
	if err != nil {
		t.Fatalf("Failed to create secret in AWS Secrets Manager: %v", err)
	}
}

// SetupVaultSecret enables KV v2 engine (if needed) and writes a secret to Vault
func SetupVaultSecret(ctx context.Context, t *testing.T, vaultContainer *VaultContainer, vaultPath string, secretData map[string]interface{}) {
	t.Helper()

	// Enable KV v2 secrets engine (if not already enabled)
	_, err := vaultContainer.Client.Logical().Write("sys/mounts/secret", map[string]interface{}{
		"type":        "kv-v2",
		"description": "KV v2 secrets engine",
	})
	if err != nil {
		// If error is that path is already in use, that's okay
		if !strings.Contains(err.Error(), "path is already in use") {
			t.Fatalf("Failed to enable KV v2 secrets engine: %v", err)
		}
	}

	_, err = vaultContainer.Client.Logical().Write(fmt.Sprintf("secret/data/%s", vaultPath), map[string]interface{}{
		"data": secretData,
	})
	if err != nil {
		t.Fatalf("Failed to write secret to Vault: %v", err)
	}
}

// SetupGCSM creates a client for real Google Cloud Secret Manager API
// Requires GOOGLE_APPLICATION_CREDENTIALS or gcloud auth to be configured
func SetupGCSM(ctx context.Context, t *testing.T) *GCSMContainer {
	t.Helper()

	// Get project ID from environment (required for real API)
	// Default to the test project if not set
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		projectID = "sstart-ci" // Default test project ID
	}

	// Create client using Application Default Credentials (ADC)
	// This will use:
	// 1. GOOGLE_APPLICATION_CREDENTIALS env var (service account key file)
	// 2. gcloud auth application-default login credentials
	// 3. GCE metadata server (if running on GCE)
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		t.Fatalf("Failed to create GCSM client: %v. Make sure credentials are configured.", err)
	}

	return &GCSMContainer{
		Container: nil, // No container for real API
		Endpoint:  "",  // Empty for real API (uses default endpoint)
		Client:    client,
		ProjectID: projectID,
		Cleanup: func() error {
			return client.Close()
		},
	}
}

// VerifyGCSMSecretExists checks if a secret exists in Google Cloud Secret Manager
// This is used to verify that predefined secrets are available for testing
func VerifyGCSMSecretExists(ctx context.Context, t *testing.T, gcsmContainer *GCSMContainer, projectID, secretID string) {
	t.Helper()

	// Use project ID from container if not provided
	if projectID == "" {
		projectID = gcsmContainer.ProjectID
	}

	// Try to access the secret to verify it exists
	secretName := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretID)
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName,
	}

	_, err := gcsmContainer.Client.AccessSecretVersion(ctx, req)
	if err != nil {
		t.Skipf("Skipping test: Secret '%s' does not exist or is not accessible. "+
			"Please create it beforehand. See tests/end2end/GCSM_SETUP.md for instructions.", secretID)
	}
}

// SetupAzureKeyVault starts an Azure Key Vault emulator container and returns the container info
// Uses Lowkey Vault, a test double for Azure Key Vault that's compatible with Azure Key Vault REST APIs
// Lowkey Vault is chosen over james-gould emulator because it doesn't require pre-generated SSL certificates,
// making it much simpler to use in automated test environments
func SetupAzureKeyVault(ctx context.Context, t *testing.T) *AzureKeyVaultContainer {
	t.Helper()

	// Lowkey Vault runs on port 8443 (HTTPS) by default
	// Wait for the port to be ready - Lowkey Vault may take a moment to start
	req := testcontainers.ContainerRequest{
		Image:        "nagyesta/lowkey-vault:4.0.0-ubi9-minimal",
		ExposedPorts: []string{"8443/tcp"},
		WaitingFor:   wait.ForListeningPort("8443/tcp"),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("Failed to start Azure Key Vault emulator container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get Azure Key Vault emulator host: %v", err)
	}

	port, err := container.MappedPort(ctx, "8443/tcp")
	if err != nil {
		t.Fatalf("Failed to get Azure Key Vault emulator port: %v", err)
	}

	// Lowkey Vault uses HTTPS and expects vault URL format: https://host:port
	vaultURL := fmt.Sprintf("https://%s:%s", host, port.Port())

	// Lowkey Vault doesn't require real Azure credentials for testing
	// Use ClientSecretCredential with dummy values - Lowkey Vault doesn't validate these
	// Using a valid UUID format for tenant ID to avoid format errors
	cred, err := azidentity.NewClientSecretCredential(
		"00000000-0000-0000-0000-000000000000", // dummy tenant ID
		"00000000-0000-0000-0000-000000000000", // dummy client ID
		"dummy-secret",                          // dummy secret
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to create Azure credential: %v", err)
	}

	// Create client - Lowkey Vault uses self-signed certificates, so we need to configure TLS
	// to skip certificate verification for testing
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skip certificate verification for testing
		},
	}
	httpClient := &http.Client{
		Transport: transport,
	}

	clientOptions := &azsecrets.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Transport: httpClient,
		},
		DisableChallengeResourceVerification: true, // Required for Lowkey Vault emulator
	}

	client, err := azsecrets.NewClient(vaultURL, cred, clientOptions)
	if err != nil {
		t.Fatalf("Failed to create Azure Key Vault client: %v", err)
	}

	return &AzureKeyVaultContainer{
		Container: container,
		VaultURL:  vaultURL,
		Client:    client,
		Cleanup: func() error {
			return container.Terminate(ctx)
		},
	}
}

// SetupAzureKeyVaultSecret creates a secret in Azure Key Vault emulator
func SetupAzureKeyVaultSecret(ctx context.Context, t *testing.T, akvContainer *AzureKeyVaultContainer, secretName string, secretData map[string]interface{}) {
	t.Helper()

	// Marshal secret data to JSON
	secretJSON, err := json.Marshal(secretData)
	if err != nil {
		t.Fatalf("Failed to marshal secret data: %v", err)
	}

	secretValue := string(secretJSON)

	// Set the secret in Azure Key Vault
	// SetSecret expects a SetSecretParameters struct with Value field
	_, err = akvContainer.Client.SetSecret(ctx, secretName, azsecrets.SetSecretParameters{
		Value: &secretValue,
	}, nil)
	if err != nil {
		t.Fatalf("Failed to create secret in Azure Key Vault: %v", err)
	}
}

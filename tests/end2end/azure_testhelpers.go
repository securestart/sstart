package end2end

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// AzureKeyVaultContainer wraps Azure Key Vault emulator container and client
type AzureKeyVaultContainer struct {
	Container testcontainers.Container
	VaultURL  string
	Client    *azsecrets.Client
	Cleanup   func() error
}

// SetupAzureKeyVault starts a Lowkey Vault container
// Lowkey Vault is a test double for Azure Key Vault that's compatible with Azure Key Vault REST APIs
// Lowkey Vault is chosen over james-gould emulator because it doesn't require pre-generated SSL certificates,
// making it much simpler to use in automated test environments
func SetupAzureKeyVault(ctx context.Context, t *testing.T) *AzureKeyVaultContainer {
	t.Helper()

	// Lowkey Vault runs on port 8443 (HTTPS) and 8080 (identity) by default
	req := testcontainers.ContainerRequest{
		Image:        "nagyesta/lowkey-vault:5.0.0",
		ExposedPorts: []string{"8443/tcp", "8080/tcp"},
		Env: map[string]string{
			"LOWKEY_ARGS": "--LOWKEY_VAULT_RELAXED_PORTS=true",
		},
		WaitingFor: wait.ForAll(wait.ForListeningPort("8443/tcp"), wait.ForListeningPort("8080/tcp")),
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

	vaultPort, err := container.MappedPort(ctx, "8443/tcp")
	if err != nil {
		t.Fatalf("Failed to get Azure Key Vault emulator port: %v", err)
	}

	identityPort, err := container.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("Failed to get Azure Key Vault identity port: %v", err)
	}

	// Lowkey Vault uses HTTPS and expects vault URL format: https://host:port
	vaultURL := fmt.Sprintf("https://%s:%s", host, vaultPort.Port())

	// Configure environment variables for Managed Identity using Lowkey Vault's built-in identity endpoint
	// Save original values to restore later
	originalIdentityEndpoint := os.Getenv("IDENTITY_ENDPOINT")
	originalIdentityHeader := os.Getenv("IDENTITY_HEADER")

	// Set IDENTITY_ENDPOINT to point to Lowkey Vault's identity endpoint on port 8080
	identityEndpoint := fmt.Sprintf("http://%s:%s/metadata/identity/oauth2/token", host, identityPort.Port())
	os.Setenv("IDENTITY_ENDPOINT", identityEndpoint)
	os.Setenv("IDENTITY_HEADER", "header")

	// Restore environment variables in cleanup
	restoreEnv := func() {
		if originalIdentityEndpoint != "" {
			os.Setenv("IDENTITY_ENDPOINT", originalIdentityEndpoint)
		} else {
			os.Unsetenv("IDENTITY_ENDPOINT")
		}
		if originalIdentityHeader != "" {
			os.Setenv("IDENTITY_HEADER", originalIdentityHeader)
		} else {
			os.Unsetenv("IDENTITY_HEADER")
		}
	}

	// Use ManagedIdentityCredential which will use IDENTITY_ENDPOINT and IDENTITY_HEADER
	credOptions := &azidentity.ManagedIdentityCredentialOptions{}
	cred, err := azidentity.NewManagedIdentityCredential(credOptions)
	if err != nil {
		restoreEnv()
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
		restoreEnv()
		t.Fatalf("Failed to create Azure Key Vault client: %v", err)
	}

	return &AzureKeyVaultContainer{
		Container: container,
		VaultURL:  vaultURL,
		Client:    client,
		Cleanup: func() error {
			restoreEnv()
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

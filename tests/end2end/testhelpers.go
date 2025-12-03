package end2end

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/hashicorp/vault/api"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	localstack "github.com/testcontainers/testcontainers-go/modules/localstack"
	"github.com/testcontainers/testcontainers-go/modules/vault"
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

// VaultwardenContainer wraps Vaultwarden container, URL, and credentials
type VaultwardenContainer struct {
	Container testcontainers.Container
	URL       string
	Email     string
	Password  string
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

// SetupVaultwarden starts a Vaultwarden container and returns the container info
func SetupVaultwarden(ctx context.Context, t *testing.T) *VaultwardenContainer {
	t.Helper()

	// Create a generic container request for vaultwarden
	req := testcontainers.ContainerRequest{
		Image:        "vaultwarden/server:latest",
		ExposedPorts: []string{"80/tcp"},
		Env: map[string]string{
			"ADMIN_TOKEN":                "test-admin-token",
			"SIGNUPS_ALLOWED":            "true",
			"I_REALLY_WANT_VOLATILE_STORAGE": "true",
		},
		WaitingFor: wait.ForHTTP("/").
			WithPort("80").
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("Failed to start vaultwarden container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get vaultwarden host: %v", err)
	}

	port, err := container.MappedPort(ctx, "80/tcp")
	if err != nil {
		t.Fatalf("Failed to get vaultwarden port: %v", err)
	}

	url := fmt.Sprintf("http://%s:%s", host, port.Port())

	// Default test credentials
	email := "test@example.com"
	password := "test-password-123"

	return &VaultwardenContainer{
		Container: container,
		URL:       url,
		Email:     email,
		Password:  password,
		Cleanup: func() error {
			return container.Terminate(ctx)
		},
	}
}

// SetupVaultwardenSecret creates a user account and a secret item in Vaultwarden
func SetupVaultwardenSecret(ctx context.Context, t *testing.T, vaultwarden *VaultwardenContainer, itemName string, noteContent string, fields map[string]string) (string, string) {
	t.Helper()

	// For vaultwarden, we need to:
	// 1. Create a user account (signup)
	// 2. Login to get access token
	// 3. Create a cipher (secret item)
	// 4. Return the item ID and access token

	// Create HTTP client
	client := &http.Client{Timeout: 30 * time.Second}

	// Step 1: Create user via admin API
	// Vaultwarden admin API requires proper format
	adminToken := "test-admin-token" // Set in container env
	createUserURL := fmt.Sprintf("%s/admin/users", vaultwarden.URL)
	createUserData := map[string]interface{}{
		"email":    vaultwarden.Email,
		"password": vaultwarden.Password,
		"name":     "Test User",
	}
	createUserJSON, _ := json.Marshal(createUserData)
	createUserReq, _ := http.NewRequestWithContext(ctx, "POST", createUserURL, strings.NewReader(string(createUserJSON)))
	createUserReq.Header.Set("Content-Type", "application/json")
	createUserReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminToken))
	
	createUserResp, err := client.Do(createUserReq)
	if err == nil {
		createUserResp.Body.Close()
		// Wait a bit for user to be fully created
		time.Sleep(500 * time.Millisecond)
	}

	// Step 2: Login to get access token
	loginURL := fmt.Sprintf("%s/identity/connect/token", vaultwarden.URL)
	deviceIdentifier := "sstart-test"
	deviceName := "sstart-test"
	deviceType := "7" // 7 = CLI
	loginData := fmt.Sprintf("grant_type=password&username=%s&password=%s&scope=api offline_access&client_id=web&device_identifier=%s&device_name=%s&device_type=%s",
		vaultwarden.Email, vaultwarden.Password, deviceIdentifier, deviceName, deviceType)

	loginReq, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(loginData))
	if err != nil {
		t.Fatalf("Failed to create login request: %v", err)
	}
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	loginResp, err := client.Do(loginReq)
	if err != nil {
		t.Fatalf("Failed to make login request: %v", err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("Login failed with status %d: %s. User may need to be created manually or via admin API.", loginResp.StatusCode, string(body))
	}

	var loginResult map[string]interface{}
	if err := json.NewDecoder(loginResp.Body).Decode(&loginResult); err != nil {
		t.Fatalf("Failed to decode login response: %v", err)
	}

	accessToken, ok := loginResult["access_token"].(string)
	if !ok {
		// Try "token" field
		accessToken, ok = loginResult["token"].(string)
		if !ok {
			t.Fatalf("Login response did not contain access_token")
		}
	}

	// accessToken is now set from login above

	// Step 3: Create cipher (secret item)
	cipherURL := fmt.Sprintf("%s/api/ciphers", vaultwarden.URL)
	
	// Build fields array
	fieldsArray := make([]map[string]interface{}, 0)
	for name, value := range fields {
		fieldsArray = append(fieldsArray, map[string]interface{}{
			"name":  name,
			"value": value,
			"type":  0, // Text field
		})
	}

	cipherData := map[string]interface{}{
		"type":  1, // Login type
		"name":  itemName,
		"notes": noteContent,
		"fields": fieldsArray,
	}

	cipherJSON, err := json.Marshal(cipherData)
	if err != nil {
		t.Fatalf("Failed to marshal cipher data: %v", err)
	}

	cipherReq, err := http.NewRequestWithContext(ctx, "POST", cipherURL, strings.NewReader(string(cipherJSON)))
	if err != nil {
		t.Fatalf("Failed to create cipher request: %v", err)
	}
	cipherReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	cipherReq.Header.Set("Content-Type", "application/json")

	cipherResp, err := client.Do(cipherReq)
	if err != nil {
		t.Fatalf("Failed to make cipher request: %v", err)
	}
	defer cipherResp.Body.Close()

	if cipherResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(cipherResp.Body)
		t.Fatalf("Create cipher failed with status %d: %s", cipherResp.StatusCode, string(body))
	}

	var cipherResult map[string]interface{}
	if err := json.NewDecoder(cipherResp.Body).Decode(&cipherResult); err != nil {
		t.Fatalf("Failed to decode cipher response: %v", err)
	}

	itemID, ok := cipherResult["Id"].(string)
	if !ok {
		itemID, ok = cipherResult["id"].(string)
		if !ok {
			t.Fatalf("Cipher response did not contain item ID")
		}
	}

	return itemID, accessToken
}

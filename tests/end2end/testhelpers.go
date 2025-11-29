package end2end

import (
	"context"
	"encoding/json"
	"fmt"
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
	localstack "github.com/testcontainers/testcontainers-go/modules/localstack"
	"github.com/testcontainers/testcontainers-go/modules/vault"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

// GCSMContainer wraps GCSM emulator container, endpoint, and client
type GCSMContainer struct {
	Container testcontainers.Container
	Endpoint  string
	Client    *secretmanager.Client
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

// SetupGCSM starts a GCSM emulator container and returns the container info
func SetupGCSM(ctx context.Context, t *testing.T) *GCSMContainer {
	t.Helper()

	// Use the official Google Cloud Secret Manager emulator image
	req := testcontainers.ContainerRequest{
		Image:        "gcr.io/google.com/cloudsdktool/cloud-sdk:emulators",
		Cmd:          []string{"gcloud", "beta", "emulators", "secret-manager", "start", "--host-port=0.0.0.0:8080"},
		ExposedPorts: []string{"8080/tcp"},
		WaitingFor:   wait.ForListeningPort("8080/tcp").WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("Failed to start GCSM emulator container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get GCSM emulator host: %v", err)
	}

	port, err := container.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("Failed to get GCSM emulator port: %v", err)
	}

	endpoint := fmt.Sprintf("%s:%s", host, port.Port())

	// Create client for the emulator
	client, err := secretmanager.NewClient(ctx,
		option.WithEndpoint(endpoint),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
		option.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatalf("Failed to create GCSM client: %v", err)
	}

	return &GCSMContainer{
		Container: container,
		Endpoint:  endpoint,
		Client:    client,
		Cleanup: func() error {
			return container.Terminate(ctx)
		},
	}
}

// SetupGCSMSecret creates a secret in Google Cloud Secret Manager (emulator)
func SetupGCSMSecret(ctx context.Context, t *testing.T, gcsmContainer *GCSMContainer, projectID, secretID string, secretData map[string]string) {
	t.Helper()

	secretJSON, err := json.Marshal(secretData)
	if err != nil {
		t.Fatalf("Failed to marshal secret data: %v", err)
	}

	// Create the secret
	createSecretReq := &secretmanagerpb.CreateSecretRequest{
		Parent:   fmt.Sprintf("projects/%s", projectID),
		SecretId: secretID,
		Secret: &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
		},
	}

	_, err = gcsmContainer.Client.CreateSecret(ctx, createSecretReq)
	if err != nil {
		// If secret already exists, that's okay
		if !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("Failed to create secret in GCSM: %v", err)
		}
	}

	// Add a version with the secret data
	addVersionReq := &secretmanagerpb.AddSecretVersionRequest{
		Parent: fmt.Sprintf("projects/%s/secrets/%s", projectID, secretID),
		Payload: &secretmanagerpb.SecretPayload{
			Data: secretJSON,
		},
	}

	_, err = gcsmContainer.Client.AddSecretVersion(ctx, addVersionReq)
	if err != nil {
		t.Fatalf("Failed to add secret version in GCSM: %v", err)
	}
}

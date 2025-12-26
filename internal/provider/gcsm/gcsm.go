package gcsm

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/dirathea/sstart/internal/provider"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GCSMConfig represents the configuration for Google Cloud Secret Manager provider
type GCSMConfig struct {
	// ProjectID is the GCP project ID where the secret is stored (required)
	ProjectID string `json:"project_id" yaml:"project_id"`
	// SecretID is the name of the secret in GCSM (required)
	SecretID string `json:"secret_id" yaml:"secret_id"`
	// Version is the secret version to fetch (optional, defaults to "latest")
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	// Endpoint is a custom endpoint URL for GCSM (optional, for local testing/emulator)
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
}

// GCSMProvider implements the provider interface for Google Cloud Secret Manager
type GCSMProvider struct {
	client *secretmanager.Client
}

func init() {
	provider.Register("gcloud_secretmanager", func() provider.Provider {
		return &GCSMProvider{}
	})
}

// Name returns the provider name
func (p *GCSMProvider) Name() string {
	return "gcloud_secretmanager"
}

// Fetch fetches secrets from Google Cloud Secret Manager
func (p *GCSMProvider) Fetch(secretContext provider.SecretContext, mapID string, config map[string]interface{}, keys map[string]string) ([]provider.KeyValue, error) {
	ctx := secretContext.Ctx
	// Convert map to strongly typed config struct
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid gcloud_secretmanager configuration: %w", err)
	}

	// Validate required fields
	if cfg.ProjectID == "" {
		return nil, fmt.Errorf("gcloud_secretmanager provider requires 'project_id' field in configuration")
	}
	if cfg.SecretID == "" {
		return nil, fmt.Errorf("gcloud_secretmanager provider requires 'secret_id' field in configuration")
	}

	if err := p.ensureClient(ctx, cfg.Endpoint); err != nil {
		return nil, fmt.Errorf("failed to initialize GCSM client: %w", err)
	}

	// Determine version (default to "latest")
	version := cfg.Version
	if version == "" {
		version = "latest"
	}

	// Build the secret name
	secretName := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", cfg.ProjectID, cfg.SecretID, version)

	// Fetch the secret from Secret Manager
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName,
	}

	result, err := p.client.AccessSecretVersion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secret from Google Cloud Secret Manager: %w", err)
	}

	// Parse the secret value (assuming JSON format)
	secretData := make(map[string]interface{})
	secretString := string(result.Payload.Data)
	if err := json.Unmarshal([]byte(secretString), &secretData); err != nil {
		// If not JSON, treat as a single value
		secretKey := strings.ToUpper(strings.ReplaceAll(mapID, "-", "_")) + "_SECRET"
		log.Printf("WARN: Secret from provider '%s' is not JSON format. Secret loaded to %s", mapID, secretKey)
		return []provider.KeyValue{
			{Key: secretKey, Value: secretString},
		}, nil
	}

	// Map keys according to configuration
	kvs := make([]provider.KeyValue, 0)
	for k, v := range secretData {
		targetKey := k

		// Check if there's a specific mapping
		if mappedKey, exists := keys[k]; exists {
			if mappedKey == "==" {
				targetKey = k // Keep same name
			} else {
				targetKey = mappedKey
			}
		} else if len(keys) == 0 {
			// No keys specified means map everything
			targetKey = k
		} else {
			// Skip keys not in the mapping
			continue
		}

		value := fmt.Sprintf("%v", v)
		kvs = append(kvs, provider.KeyValue{
			Key:   targetKey,
			Value: value,
		})
	}

	return kvs, nil
}

func (p *GCSMProvider) ensureClient(ctx context.Context, endpoint string) error {
	if p.client != nil {
		return nil
	}

	// Build client options
	opts := []option.ClientOption{}

	// If using a custom endpoint (e.g., emulator), configure it
	if endpoint != "" {
		opts = append(opts, option.WithEndpoint(endpoint))
		opts = append(opts, option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
		// For emulator, we don't need real credentials
		opts = append(opts, option.WithoutAuthentication())
	} else {
		// For production, use default credentials (ADC - Application Default Credentials)
		// This will use GOOGLE_APPLICATION_CREDENTIALS env var or metadata server
		// No need to set anything, ADC is the default
	}

	// Create client
	client, err := secretmanager.NewClient(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create GCSM client: %w", err)
	}

	p.client = client
	return nil
}

// parseConfig converts a map[string]interface{} to GCSMConfig
func parseConfig(config map[string]interface{}) (*GCSMConfig, error) {
	// Use JSON marshaling/unmarshaling for clean conversion
	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var cfg GCSMConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}


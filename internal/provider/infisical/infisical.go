package infisical

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/dirathea/sstart/internal/provider"
	infisical "github.com/infisical/go-sdk"
)

// InfisicalConfig represents the configuration for Infisical provider
type InfisicalConfig struct {
	// ProjectID is the Infisical project ID (required)
	ProjectID string `json:"project_id" yaml:"project_id"`
	// Environment is the environment slug (e.g., dev, prod) (required)
	Environment string `json:"environment" yaml:"environment"`
	// Path is the secret path from where to fetch secrets (required)
	Path string `json:"path" yaml:"path"`
	// Recursive indicates whether to fetch secrets recursively from subdirectories (optional, default: false)
	Recursive *bool `json:"recursive,omitempty" yaml:"recursive,omitempty"`
	// IncludeImports specifies whether to include imported secrets (optional, default: false)
	IncludeImports *bool `json:"include_imports,omitempty" yaml:"include_imports,omitempty"`
	// ExpandSecrets determines whether to expand secret references (optional, default: false)
	ExpandSecrets *bool `json:"expand_secrets,omitempty" yaml:"expand_secrets,omitempty"`
}

// InfisicalProvider implements the provider interface for Infisical
type InfisicalProvider struct {
	client infisical.InfisicalClientInterface
}

func init() {
	provider.Register("infisical", func() provider.Provider {
		return &InfisicalProvider{}
	})
}

// Name returns the provider name
func (p *InfisicalProvider) Name() string {
	return "infisical"
}

// Fetch fetches secrets from Infisical
func (p *InfisicalProvider) Fetch(ctx context.Context, mapID string, config map[string]interface{}) ([]provider.KeyValue, error) {
	// Convert map to strongly typed config struct
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid infisical configuration: %w", err)
	}

	// Validate required fields
	if cfg.ProjectID == "" {
		return nil, fmt.Errorf("infisical provider requires 'project_id' field in configuration")
	}
	if cfg.Environment == "" {
		return nil, fmt.Errorf("infisical provider requires 'environment' field in configuration")
	}
	if cfg.Path == "" {
		return nil, fmt.Errorf("infisical provider requires 'path' field in configuration")
	}

	// Ensure client is initialized
	if err := p.ensureClient(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize Infisical client: %w", err)
	}

	// Set default values for optional parameters
	recursive := false
	if cfg.Recursive != nil {
		recursive = *cfg.Recursive
	}

	includeImports := false
	if cfg.IncludeImports != nil {
		includeImports = *cfg.IncludeImports
	}

	expandSecrets := false
	if cfg.ExpandSecrets != nil {
		expandSecrets = *cfg.ExpandSecrets
	}

	// Build ListSecretsOptions
	listOptions := infisical.ListSecretsOptions{
		ProjectID:              cfg.ProjectID,
		Environment:            cfg.Environment,
		SecretPath:             cfg.Path,
		Recursive:              recursive,
		IncludeImports:         includeImports,
		ExpandSecretReferences: expandSecrets,
	}

	// Fetch secrets using the SDK
	secrets, err := p.client.Secrets().List(listOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets from Infisical: %w", err)
	}

	// Convert secrets to key-value pairs
	secretData := make(map[string]interface{})
	for _, secret := range secrets {
		// Use the secret key as the key, and the secret value as the value
		secretData[secret.SecretKey] = secret.SecretValue
	}

	// Map keys according to configuration
	kvs := make([]provider.KeyValue, 0)
	for k, v := range secretData {
		value := fmt.Sprintf("%v", v)
		kvs = append(kvs, provider.KeyValue{
			Key:   k,
			Value: value,
		})
	}

	return kvs, nil
}

// ensureClient initializes the Infisical client if not already initialized
func (p *InfisicalProvider) ensureClient(ctx context.Context) error {
	if p.client != nil {
		return nil
	}

	// Check for required environment variables
	clientID := os.Getenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID")
	clientSecret := os.Getenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET")

	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID and INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET environment variables are required")
	}

	// Get site URL from environment variable (optional, defaults to https://app.infisical.com)
	siteURL := os.Getenv("INFISICAL_SITE_URL")

	// Create client config
	clientConfig := infisical.Config{}
	if siteURL != "" {
		clientConfig.SiteUrl = siteURL
	}

	// Create client with config
	client := infisical.NewInfisicalClient(ctx, clientConfig)

	// Authenticate using universal auth (pass env vars as parameters)
	_, err := client.Auth().UniversalAuthLogin(clientID, clientSecret)
	if err != nil {
		return fmt.Errorf("failed to authenticate with Infisical: %w", err)
	}

	p.client = client
	return nil
}

// parseConfig converts a map[string]interface{} to InfisicalConfig
func parseConfig(config map[string]interface{}) (*InfisicalConfig, error) {
	// Use JSON marshaling/unmarshaling for clean conversion
	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var cfg InfisicalConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

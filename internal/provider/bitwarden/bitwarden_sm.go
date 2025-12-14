package bitwarden

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bitwarden/sdk-go"
	"github.com/dirathea/sstart/internal/provider"
)

// BitwardenSMConfig represents the configuration for Bitwarden Secret Manager provider
// Note: Access token must be provided via BITWARDEN_SM_ACCESS_TOKEN environment variable
type BitwardenSMConfig struct {
	// ServerURL is the Bitwarden server URL (optional, defaults to BITWARDEN_SERVER_URL env var or https://vault.bitwarden.com)
	ServerURL string `json:"server_url,omitempty" yaml:"server_url,omitempty"`
	// OrganizationID is the ID of the organization in Bitwarden Secret Manager (required)
	OrganizationID string `json:"organization_id" yaml:"organization_id"`
	// ProjectID is the ID of the project in Bitwarden Secret Manager (required)
	ProjectID string `json:"project_id" yaml:"project_id"`
}

// BitwardenSMProvider implements the provider interface for Bitwarden Secret Manager
type BitwardenSMProvider struct {
	client      sdk.BitwardenClientInterface
	serverURL   string
	accessToken string
}

func init() {
	provider.Register("bitwarden_sm", func() provider.Provider {
		return &BitwardenSMProvider{}
	})
}

// Name returns the provider name
func (p *BitwardenSMProvider) Name() string {
	return "bitwarden_sm"
}

// Fetch fetches all secrets from a Bitwarden Secret Manager project
// Only Key-Value pairs are extracted from secrets. Note fields are ignored.
func (p *BitwardenSMProvider) Fetch(ctx context.Context, mapID string, config map[string]interface{}) ([]provider.KeyValue, error) {
	// Convert map to strongly typed config struct
	cfg, err := parseSMConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid bitwarden_sm configuration: %w", err)
	}

	// Validate required fields
	if cfg.OrganizationID == "" {
		return nil, fmt.Errorf("bitwarden_sm provider requires 'organization_id' field in configuration")
	}
	if cfg.ProjectID == "" {
		return nil, fmt.Errorf("bitwarden_sm provider requires 'project_id' field in configuration")
	}

	// Get server URL from config or environment or default
	serverURL := cfg.ServerURL
	if serverURL == "" {
		serverURL = getEnvOrDefault("BITWARDEN_SERVER_URL", "https://vault.bitwarden.com")
	}
	// Ensure server URL doesn't end with /
	serverURL = strings.TrimSuffix(serverURL, "/")

	// Get access token from environment variable (required)
	accessToken := getEnv("BITWARDEN_SM_ACCESS_TOKEN")
	if accessToken == "" {
		return nil, fmt.Errorf("bitwarden_sm provider requires BITWARDEN_SM_ACCESS_TOKEN environment variable")
	}

	if err := p.ensureClient(serverURL, accessToken); err != nil {
		return nil, fmt.Errorf("failed to initialize Bitwarden client: %w", err)
	}

	// List all secret identifiers from the organization
	secretsListResponse, err := p.client.Secrets().List(cfg.OrganizationID)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets from Bitwarden Secret Manager: %w", err)
	}

	if secretsListResponse == nil || len(secretsListResponse.Data) == 0 {
		return nil, fmt.Errorf("no secrets found in organization '%s'", cfg.OrganizationID)
	}

	// Collect all secret IDs
	secretIDs := make([]string, 0, len(secretsListResponse.Data))
	for _, secretID := range secretsListResponse.Data {
		secretIDs = append(secretIDs, secretID.ID)
	}

	// Fetch all secrets at once
	secretsResponse, err := p.client.Secrets().GetByIDS(secretIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secrets from Bitwarden Secret Manager: %w", err)
	}

	if secretsResponse == nil || secretsResponse.Data == nil || len(secretsResponse.Data) == 0 {
		return nil, fmt.Errorf("no secret data returned from Bitwarden Secret Manager")
	}

	// Filter secrets by project ID and build secret data map
	secretData := make(map[string]interface{})
	for _, secret := range secretsResponse.Data {
		// Only include secrets that belong to the specified project
		if secret.ProjectID != nil && *secret.ProjectID == cfg.ProjectID {
			// Use only Key and Value fields (Note field is ignored)
			if secret.Key != "" {
				if secret.Value != "" {
					secretData[secret.Key] = secret.Value
				} else {
					// If Value is empty, still include Key with empty value
					secretData[secret.Key] = ""
				}
			}
		}
	}

	if len(secretData) == 0 {
		return nil, fmt.Errorf("no secrets found in project '%s' for organization '%s'", cfg.ProjectID, cfg.OrganizationID)
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

func (p *BitwardenSMProvider) ensureClient(serverURL, accessToken string) error {
	if p.client != nil && p.serverURL == serverURL && p.accessToken == accessToken {
		return nil
	}

	// Close existing client if any
	if p.client != nil {
		p.client.Close()
	}

	// Determine API and Identity URLs
	// For Bitwarden cloud (vault.bitwarden.com), use separate API and Identity URLs
	// For self-hosted instances, append /api and /identity to the base URL
	var apiURL, identityURL string
	if serverURL == "https://vault.bitwarden.com" || serverURL == "https://vault.bitwarden.com/" {
		apiURL = "https://api.bitwarden.com"
		identityURL = "https://identity.bitwarden.com"
	} else {
		// Self-hosted or custom server
		apiURL = serverURL + "/api"
		identityURL = serverURL + "/identity"
	}

	// Create SDK client
	client, err := sdk.NewBitwardenClient(&apiURL, &identityURL)
	if err != nil {
		return fmt.Errorf("failed to create Bitwarden client: %w", err)
	}

	// Login with access token (stateFile is nil to not persist state)
	stateFile := (*string)(nil)
	if err := client.AccessTokenLogin(accessToken, stateFile); err != nil {
		client.Close()
		return fmt.Errorf("failed to authenticate with Bitwarden: %w", err)
	}

	p.client = client
	p.serverURL = serverURL
	p.accessToken = accessToken

	return nil
}

// parseSMConfig converts a map[string]interface{} to BitwardenSMConfig
func parseSMConfig(config map[string]interface{}) (*BitwardenSMConfig, error) {
	// Use JSON marshaling/unmarshaling for clean conversion
	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var cfg BitwardenSMConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

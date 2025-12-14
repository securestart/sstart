package doppler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/dirathea/sstart/internal/provider"
)

// DopplerConfig represents the configuration for Doppler provider
type DopplerConfig struct {
	// Project is the Doppler project name (required)
	Project string `json:"project" yaml:"project"`
	// Config is the Doppler config/environment name (required, e.g., "dev", "staging", "prod")
	Config string `json:"config" yaml:"config"`
	// APIHost is the Doppler API host (optional, defaults to "https://api.doppler.com")
	APIHost string `json:"api_host,omitempty" yaml:"api_host,omitempty"`
}

// dopplerSecretInfo represents a single secret from the Doppler API response
type dopplerSecretInfo struct {
	Raw                string `json:"raw"`
	Computed           string `json:"computed"`
	Note               string `json:"note"`
	RawVisibility      string `json:"rawVisibility"`
	ComputedVisibility string `json:"computedVisibility"`
}

// dopplerSecretsResponse represents the response from the Doppler API secrets endpoint
type dopplerSecretsResponse struct {
	Secrets map[string]dopplerSecretInfo `json:"secrets"`
}

// DopplerProvider implements the provider interface for Doppler
type DopplerProvider struct {
	client *http.Client
}

func init() {
	provider.Register("doppler", func() provider.Provider {
		return &DopplerProvider{
			client: &http.Client{
				Timeout: 30 * time.Second,
			},
		}
	})
}

// Name returns the provider name
func (p *DopplerProvider) Name() string {
	return "doppler"
}

// Fetch fetches secrets from Doppler
func (p *DopplerProvider) Fetch(ctx context.Context, mapID string, config map[string]interface{}) ([]provider.KeyValue, error) {
	// Parse and validate configuration
	cfg, err := validateConfig(config)
	if err != nil {
		return nil, err
	}

	// Get service token from environment
	serviceToken := os.Getenv("DOPPLER_TOKEN")
	if serviceToken == "" {
		return nil, fmt.Errorf("doppler provider requires 'DOPPLER_TOKEN' environment variable")
	}

	// Set default API host if not provided
	apiHost := cfg.APIHost
	if apiHost == "" {
		apiHost = "https://api.doppler.com"
	}

	// Build API URL with properly encoded query parameters
	// According to Doppler API docs: https://docs.doppler.com/reference/api
	// Use /v3/configs/config/secrets endpoint to get detailed response
	// Set include_managed_secrets=false to exclude Doppler's auto-generated secrets (DOPPLER_CONFIG, DOPPLER_ENVIRONMENT, DOPPLER_PROJECT)
	apiURL := fmt.Sprintf("%s/v3/configs/config/secrets?project=%s&config=%s&include_managed_secrets=false",
		apiHost, url.QueryEscape(cfg.Project), url.QueryEscape(cfg.Config))

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", serviceToken))
	req.Header.Set("Accept", "application/json")

	// Make HTTP request
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secrets from Doppler: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("doppler API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var response dopplerSecretsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// Map keys according to configuration
	// Use computed value as it resolves secret references (e.g., ${USER})
	kvs := make([]provider.KeyValue, 0)
	for secretName, secretInfo := range response.Secrets {
		// Use computed value (resolves references like ${USER})
		kvs = append(kvs, provider.KeyValue{
			Key:   secretName,
			Value: secretInfo.Computed,
		})
	}

	return kvs, nil
}

// validateConfig parses and validates the Doppler configuration
func validateConfig(config map[string]interface{}) (*DopplerConfig, error) {
	// Parse config map to strongly typed struct
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid doppler configuration: %w", err)
	}

	// Validate required fields
	if cfg.Project == "" {
		return nil, fmt.Errorf("doppler provider requires 'project' field in configuration")
	}
	if cfg.Config == "" {
		return nil, fmt.Errorf("doppler provider requires 'config' field in configuration")
	}

	return cfg, nil
}

// parseConfig converts a map[string]interface{} to DopplerConfig
func parseConfig(config map[string]interface{}) (*DopplerConfig, error) {
	// Use JSON marshaling/unmarshaling for clean conversion
	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var cfg DopplerConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

package bitwarden

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bitwarden/sdk-go"
	"github.com/dirathea/sstart/internal/provider"
)

// BitwardenSMConfig represents the configuration for Bitwarden Secret Manager provider
// Note: Authentication credentials (email, password, access_token) must be provided via environment variables
// BITWARDEN_EMAIL, BITWARDEN_PASSWORD, or BITWARDEN_ACCESS_TOKEN
type BitwardenSMConfig struct {
	// ServerURL is the Bitwarden server URL (optional, defaults to BITWARDEN_SERVER_URL env var or https://vault.bitwarden.com)
	ServerURL string `json:"server_url,omitempty" yaml:"server_url,omitempty"`
	// SecretID is the ID of the secret item in Bitwarden Secret Manager (required)
	SecretID string `json:"secret_id" yaml:"secret_id"`
	// ParseNoteAsJSON if true, attempts to parse the Note field as JSON to extract multiple key-value pairs
	// If false or Note is not JSON, only Key and Value fields are used (default: false)
	ParseNoteAsJSON bool `json:"parse_note_as_json,omitempty" yaml:"parse_note_as_json,omitempty"`
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

// Fetch fetches secrets from Bitwarden Secret Manager
// According to the SDK API (https://github.com/bitwarden/sdk-sm/tree/main/languages/go#get-a-secret),
// secrets have Key, Value, and an optional Note field.
func (p *BitwardenSMProvider) Fetch(ctx context.Context, mapID string, config map[string]interface{}, keys map[string]string) ([]provider.KeyValue, error) {
	// Convert map to strongly typed config struct
	cfg, err := parseSMConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid bitwarden_sm configuration: %w", err)
	}

	// Validate required fields
	if cfg.SecretID == "" {
		return nil, fmt.Errorf("bitwarden_sm provider requires 'secret_id' field in configuration")
	}

	// Get server URL from config or environment or default
	serverURL := cfg.ServerURL
	if serverURL == "" {
		serverURL = getEnvOrDefault("BITWARDEN_SERVER_URL", "https://vault.bitwarden.com")
	}
	// Ensure server URL doesn't end with /
	serverURL = strings.TrimSuffix(serverURL, "/")

	// Get access token from environment variable only
	accessToken := getEnv("BITWARDEN_ACCESS_TOKEN")

	// If no access token, try to login using email/password from environment variables
	if accessToken == "" {
		email := getEnv("BITWARDEN_EMAIL")
		password := getEnv("BITWARDEN_PASSWORD")

		if email == "" || password == "" {
			return nil, fmt.Errorf("bitwarden_sm provider requires either BITWARDEN_ACCESS_TOKEN or both BITWARDEN_EMAIL and BITWARDEN_PASSWORD environment variables")
		}

		var err error
		accessToken, err = p.login(ctx, serverURL, email, password)
		if err != nil {
			return nil, fmt.Errorf("failed to login to Bitwarden: %w", err)
		}
	}

	if err := p.ensureClient(serverURL, accessToken); err != nil {
		return nil, fmt.Errorf("failed to initialize Bitwarden client: %w", err)
	}

	// Fetch the secret from Bitwarden Secret Manager using SDK
	secret, err := p.client.Secrets().Get(cfg.SecretID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secret from Bitwarden Secret Manager: %w", err)
	}

	// Build secret data map
	secretData := make(map[string]interface{})

	// Always include Key and Value if they exist
	if secret.Key != "" {
		if secret.Value != "" {
			secretData[secret.Key] = secret.Value
		} else {
			// If Value is empty, still include Key with empty value
			secretData[secret.Key] = ""
		}
	}

	// Handle Note field
	if secret.Note != "" {
		if cfg.ParseNoteAsJSON {
			// Try to parse Note as JSON
			var noteData map[string]interface{}
			if err := json.Unmarshal([]byte(secret.Note), &noteData); err == nil {
				// Successfully parsed as JSON, merge with existing data
				for k, v := range noteData {
					secretData[k] = v
				}
			} else {
				// Note is not valid JSON, include it as a simple field
				secretData["note"] = secret.Note
			}
		} else {
			// Include Note as a simple field
			secretData["note"] = secret.Note
		}
	}

	if len(secretData) == 0 {
		return nil, fmt.Errorf("bitwarden secret '%s' has no key, value, or note content", cfg.SecretID)
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

// BitwardenLoginResponse represents the login response
type BitwardenLoginResponse struct {
	AccessToken string `json:"access_token"`
	Token       string `json:"token"` // Some APIs use "token" instead of "access_token"
}

func (p *BitwardenSMProvider) login(ctx context.Context, serverURL, email, password string) (string, error) {
	url := fmt.Sprintf("%s/identity/connect/token", serverURL)

	// Bitwarden uses form-encoded data for login
	// device_identifier, device_name, and device_type are required
	deviceIdentifier := "sstart-cli"
	deviceName := "sstart-cli"
	deviceType := "7" // 7 = CLI
	formData := fmt.Sprintf("grant_type=password&username=%s&password=%s&scope=api offline_access&client_id=web&device_identifier=%s&device_name=%s&device_type=%s",
		email, password, deviceIdentifier, deviceName, deviceType)

	// Create a temporary HTTP client for login
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(formData))
	if err != nil {
		return "", fmt.Errorf("failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make login request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("bitwarden login returned status %d: %s", resp.StatusCode, string(body))
	}

	var loginResp BitwardenLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return "", fmt.Errorf("failed to decode login response: %w", err)
	}

	// Some APIs return "access_token", others return "token"
	if loginResp.AccessToken != "" {
		return loginResp.AccessToken, nil
	}
	if loginResp.Token != "" {
		return loginResp.Token, nil
	}

	return "", fmt.Errorf("login response did not contain access token")
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

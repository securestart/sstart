package bitwarden

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dirathea/sstart/internal/provider"
)

// BitwardenConfig represents the configuration for Bitwarden provider
type BitwardenConfig struct {
	// ServerURL is the Bitwarden server URL (optional, defaults to https://vault.bitwarden.com)
	ServerURL string `json:"server_url,omitempty" yaml:"server_url,omitempty"`
	// Email is the Bitwarden account email for authentication (required if access_token not provided)
	Email string `json:"email,omitempty" yaml:"email,omitempty"`
	// Password is the Bitwarden account password for authentication (required if access_token not provided)
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
	// AccessToken is the Bitwarden access token (optional, if provided, email/password not needed)
	AccessToken string `json:"access_token,omitempty" yaml:"access_token,omitempty"`
	// SecretID is the ID of the secret item in Bitwarden (required)
	SecretID string `json:"secret_id" yaml:"secret_id"`
	// Format specifies how to parse the secret: "note" (JSON) or "fields" (key-value pairs)
	Format string `json:"format,omitempty" yaml:"format,omitempty"`
}

// BitwardenProvider implements the provider interface for Bitwarden
type BitwardenProvider struct {
	client      *http.Client
	serverURL   string
	accessToken string
}

func init() {
	provider.Register("bitwarden", func() provider.Provider {
		return &BitwardenProvider{}
	})
}

// Name returns the provider name
func (p *BitwardenProvider) Name() string {
	return "bitwarden"
}

// Fetch fetches secrets from Bitwarden
func (p *BitwardenProvider) Fetch(ctx context.Context, mapID string, config map[string]interface{}, keys map[string]string) ([]provider.KeyValue, error) {
	// Convert map to strongly typed config struct
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid bitwarden configuration: %w", err)
	}

	// Validate required fields
	if cfg.SecretID == "" {
		return nil, fmt.Errorf("bitwarden provider requires 'secret_id' field in configuration")
	}

	// Validate format
	format := strings.ToLower(cfg.Format)
	if format != "" && format != "note" && format != "fields" {
		return nil, fmt.Errorf("bitwarden provider 'format' must be either 'note' or 'fields' (got: %s)", cfg.Format)
	}
	if format == "" {
		format = "note" // Default to note format
	}

	// Get server URL from config or environment or default
	serverURL := cfg.ServerURL
	if serverURL == "" {
		serverURL = getEnvOrDefault("BITWARDEN_SERVER_URL", "https://vault.bitwarden.com")
	}
	// Ensure server URL doesn't end with /
	serverURL = strings.TrimSuffix(serverURL, "/")

	// Get access token
	accessToken := cfg.AccessToken
	if accessToken == "" {
		accessToken = getEnvOrDefault("BITWARDEN_ACCESS_TOKEN", "")
	}

	// If no access token, try to login
	if accessToken == "" {
		email := cfg.Email
		if email == "" {
			email = getEnvOrDefault("BITWARDEN_EMAIL", "")
		}
		password := cfg.Password
		if password == "" {
			password = getEnvOrDefault("BITWARDEN_PASSWORD", "")
		}

		if email == "" || password == "" {
			return nil, fmt.Errorf("bitwarden provider requires either 'access_token' or 'email' and 'password' in configuration (or environment variables BITWARDEN_ACCESS_TOKEN or BITWARDEN_EMAIL/BITWARDEN_PASSWORD)")
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

	// Fetch the secret from Bitwarden
	item, err := p.fetchItem(ctx, cfg.SecretID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secret from Bitwarden: %w", err)
	}

	// Parse secrets based on format
	var secretData map[string]interface{}
	if format == "note" {
		// Parse note as JSON
		if item.Notes == "" {
			return nil, fmt.Errorf("bitwarden item '%s' has no note content for 'note' format", cfg.SecretID)
		}
		if err := json.Unmarshal([]byte(item.Notes), &secretData); err != nil {
			return nil, fmt.Errorf("failed to parse note as JSON for bitwarden item '%s': %w", cfg.SecretID, err)
		}
	} else {
		// Parse fields as key-value pairs
		secretData = make(map[string]interface{})
		for _, field := range item.Fields {
			if field.Name != "" {
				secretData[field.Name] = field.Value
			}
		}
		if len(secretData) == 0 {
			return nil, fmt.Errorf("bitwarden item '%s' has no custom fields for 'fields' format", cfg.SecretID)
		}
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

// BitwardenItem represents a Bitwarden item
// Bitwarden API uses "Id", "Notes", "Fields" with capital letters
type BitwardenItem struct {
	ID     string           `json:"Id"`
	Notes  string           `json:"Notes"`
	Fields []BitwardenField `json:"Fields"`
}

// BitwardenField represents a custom field in a Bitwarden item
type BitwardenField struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
	Type  int    `json:"Type"`
}

// BitwardenAPIResponse represents the response from Bitwarden API
// The API may return the item directly or wrapped in a data field
type BitwardenAPIResponse struct {
	Data   *BitwardenItem `json:"data,omitempty"`
	ID     string          `json:"Id,omitempty"` // Bitwarden uses "Id" with capital I
	Notes  string          `json:"Notes,omitempty"`
	Fields []BitwardenField `json:"Fields,omitempty"`
}

func (p *BitwardenProvider) ensureClient(serverURL, accessToken string) error {
	if p.client != nil && p.serverURL == serverURL && p.accessToken == accessToken {
		return nil
	}

	p.client = &http.Client{
		Timeout: 30 * time.Second,
	}
	p.serverURL = serverURL
	p.accessToken = accessToken

	return nil
}

func (p *BitwardenProvider) fetchItem(ctx context.Context, itemID string) (*BitwardenItem, error) {
	// Use Bitwarden API to fetch the item
	// For vaultwarden/Bitwarden, we need to authenticate first and then fetch the item
	// The API endpoint is: GET /api/ciphers/{id}
	
	url := fmt.Sprintf("%s/api/ciphers/%s", p.serverURL, itemID)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.accessToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bitwarden API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read the body first, then try both formats
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Try direct item format
	var item BitwardenItem
	if err := json.Unmarshal(bodyBytes, &item); err == nil && item.ID != "" {
		return &item, nil
	}

	// Try wrapped format
	var apiResp BitwardenAPIResponse
	if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Handle both response formats: direct item or wrapped in data field
	if apiResp.Data != nil && apiResp.Data.ID != "" {
		// Wrapped in data field
		return apiResp.Data, nil
	} else if apiResp.ID != "" {
		// Direct item with capital I
		return &BitwardenItem{
			ID:     apiResp.ID,
			Notes:  apiResp.Notes,
			Fields: apiResp.Fields,
		}, nil
	}

	return nil, fmt.Errorf("invalid response format from Bitwarden API: %s", string(bodyBytes))
}

// BitwardenLoginRequest represents the login request
type BitwardenLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// BitwardenLoginResponse represents the login response
type BitwardenLoginResponse struct {
	AccessToken string `json:"access_token"`
	Token       string `json:"token"` // Some APIs use "token" instead of "access_token"
}

func (p *BitwardenProvider) login(ctx context.Context, serverURL, email, password string) (string, error) {
	url := fmt.Sprintf("%s/identity/connect/token", serverURL)

	// Bitwarden uses form-encoded data for login
	// device_identifier, device_name, and device_type are required
	deviceIdentifier := "sstart-cli"
	deviceName := "sstart-cli"
	deviceType := "7" // 7 = CLI
	formData := fmt.Sprintf("grant_type=password&username=%s&password=%s&scope=api offline_access&client_id=web&device_identifier=%s&device_name=%s&device_type=%s", 
		email, password, deviceIdentifier, deviceName, deviceType)
	
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(formData))
	if err != nil {
		return "", fmt.Errorf("failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
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

// parseConfig converts a map[string]interface{} to BitwardenConfig
func parseConfig(config map[string]interface{}) (*BitwardenConfig, error) {
	// Use JSON marshaling/unmarshaling for clean conversion
	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var cfg BitwardenConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// getEnvOrDefault gets an environment variable or returns a default value
func getEnvOrDefault(key, defaultValue string) string {
	if val := getEnv(key); val != "" {
		return val
	}
	return defaultValue
}

// getEnv gets an environment variable (mocked for testing)
var getEnv = os.Getenv

// SetGetEnvForTesting allows tests to override the getEnv function
func SetGetEnvForTesting(fn func(string) string) {
	getEnv = fn
}

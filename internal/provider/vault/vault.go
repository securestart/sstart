package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/dirathea/sstart/internal/provider"
	"github.com/hashicorp/vault/api"
)

const (
	// AuthMethodToken uses a static Vault token for authentication
	AuthMethodToken = "token"
	// AuthMethodOIDC uses OIDC/JWT authentication via SSO
	AuthMethodOIDC = "oidc"
	// AuthMethodJWT is an alias for OIDC authentication
	AuthMethodJWT = "jwt"

	// DefaultJWTAuthMount is the default mount path for JWT auth
	DefaultJWTAuthMount = "jwt"
)

// VaultAuthConfig represents authentication configuration for Vault
type VaultAuthConfig struct {
	// Method specifies the authentication method: "token" (default), "oidc", or "jwt"
	Method string `json:"method,omitempty" yaml:"method,omitempty"`
	// Role is the Vault role to authenticate as (required when using oidc/jwt auth)
	Role string `json:"role,omitempty" yaml:"role,omitempty"`
	// Mount is the mount path for the auth backend (optional, defaults to "jwt" for oidc/jwt)
	Mount string `json:"mount,omitempty" yaml:"mount,omitempty"`
	// Token is the Vault authentication token (optional, defaults to VAULT_TOKEN env var)
	Token string `json:"token,omitempty" yaml:"token,omitempty"`
}

// VaultConfig represents the configuration for HashiCorp Vault provider
type VaultConfig struct {
	// Address is the Vault server address (optional, defaults to VAULT_ADDR env var)
	Address string `json:"address,omitempty" yaml:"address,omitempty"`
	// Path is the path to the secret in Vault (required)
	Path string `json:"path" yaml:"path"`
	// Mount is the secret engine mount path (optional, defaults to "secret")
	Mount string `json:"mount,omitempty" yaml:"mount,omitempty"`
	// Auth contains authentication configuration
	Auth *VaultAuthConfig `json:"auth,omitempty" yaml:"auth,omitempty"`

	// Internal: SSO tokens injected by the collector
	SSOAccessToken string `json:"-" yaml:"-"`
	SSOIDToken     string `json:"-" yaml:"-"`
}

// VaultProvider implements the provider interface for HashiCorp Vault
type VaultProvider struct {
	client *api.Client
}

func init() {
	provider.Register("vault", func() provider.Provider {
		return &VaultProvider{}
	})
}

// Name returns the provider name
func (p *VaultProvider) Name() string {
	return "vault"
}

// Fetch fetches secrets from HashiCorp Vault
func (p *VaultProvider) Fetch(secretContext provider.SecretContext, mapID string, config map[string]interface{}, keys map[string]string) ([]provider.KeyValue, error) {
	ctx := secretContext.Ctx
	// Convert map to strongly typed config struct
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid vault configuration: %w", err)
	}

	// Validate required fields
	if cfg.Path == "" {
		return nil, fmt.Errorf("vault provider requires 'path' field in configuration")
	}

	if err := p.ensureClient(ctx, cfg); err != nil {
		return nil, fmt.Errorf("failed to initialize Vault client: %w", err)
	}

	// Determine mount path (default to "secret")
	mount := cfg.Mount
	if mount == "" {
		mount = "secret"
	}

	// Clean the path
	cleanPath := strings.TrimPrefix(cfg.Path, "/")

	// Try KV v2 format first (mount/data/path)
	secretPath := fmt.Sprintf("%s/data/%s", mount, cleanPath)
	secret, err := p.client.Logical().ReadWithContext(ctx, secretPath)

	// If KV v2 path not found (nil secret with no error), try KV v1 format (mount/path)
	if secret == nil && err == nil {
		secretPath = fmt.Sprintf("%s/%s", mount, cleanPath)
		secret, err = p.client.Logical().ReadWithContext(ctx, secretPath)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to read secret from Vault at path '%s': %w", secretPath, err)
	}

	if secret == nil {
		return nil, fmt.Errorf("secret not found at path '%s' (tried both KV v1 and v2 formats)", cfg.Path)
	}

	// Extract data from the secret (KV v2 format stores data under "data" key)
	var secretData map[string]interface{}
	if data, exists := secret.Data["data"]; exists {
		// KV v2 format - data is nested under "data" key
		if dataMap, ok := data.(map[string]interface{}); ok {
			secretData = dataMap
		}
	} else {
		// KV v1 format or direct data - data is at the root
		secretData = secret.Data
	}

	if secretData == nil {
		return nil, fmt.Errorf("no data found in secret at path '%s'", secretPath)
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

		// Convert value to string
		var value string
		switch val := v.(type) {
		case string:
			value = val
		case []byte:
			value = string(val)
		default:
			// For complex types, JSON encode
			jsonBytes, err := json.Marshal(val)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize value for key '%s': %w", k, err)
			}
			value = string(jsonBytes)
		}

		kvs = append(kvs, provider.KeyValue{
			Key:   targetKey,
			Value: value,
		})
	}

	return kvs, nil
}

func (p *VaultProvider) ensureClient(ctx context.Context, cfg *VaultConfig) error {
	if p.client != nil {
		return nil
	}

	// Create default config
	apiCfg := api.DefaultConfig()

	// Read environment variables first
	if err := apiCfg.ReadEnvironment(); err != nil {
		return fmt.Errorf("failed to read environment: %w", err)
	}

	// Override address if provided
	if cfg.Address != "" {
		apiCfg.Address = cfg.Address
	} else if apiCfg.Address == "" {
		// If VAULT_ADDR is not set, use default
		apiCfg.Address = "http://127.0.0.1:8200"
	}

	// Create client
	client, err := api.NewClient(apiCfg)
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Determine auth method
	authMethod := AuthMethodToken
	if cfg.Auth != nil && cfg.Auth.Method != "" {
		authMethod = strings.ToLower(cfg.Auth.Method)
	}

	switch authMethod {
	case AuthMethodOIDC, AuthMethodJWT:
		// Use JWT/OIDC authentication with SSO tokens
		if err := p.authenticateWithJWT(ctx, client, cfg); err != nil {
			return err
		}
	case AuthMethodToken:
		// Use token-based authentication
		token := ""
		if cfg.Auth != nil {
			token = cfg.Auth.Token
		}
		if err := p.authenticateWithToken(client, token); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported auth method: %s (supported: token, oidc, jwt)", authMethod)
	}

	p.client = client
	return nil
}

// authenticateWithToken sets up token-based authentication
func (p *VaultProvider) authenticateWithToken(client *api.Client, token string) error {
	// Set token if provided, otherwise use VAULT_TOKEN env var
	if token != "" {
		client.SetToken(token)
	} else {
		// Try to get from environment
		if envToken := os.Getenv("VAULT_TOKEN"); envToken != "" {
			client.SetToken(envToken)
		}
	}

	// Verify client has a token
	if client.Token() == "" {
		return fmt.Errorf("vault authentication token is required (set 'auth.token' in config or VAULT_TOKEN environment variable)")
	}

	return nil
}

// authenticateWithJWT authenticates using JWT/OIDC with SSO tokens
func (p *VaultProvider) authenticateWithJWT(ctx context.Context, client *api.Client, cfg *VaultConfig) error {
	// Get the JWT token - prefer ID token for OIDC, fall back to access token
	jwtToken := cfg.SSOIDToken
	if jwtToken == "" {
		jwtToken = cfg.SSOAccessToken
	}

	if jwtToken == "" {
		return fmt.Errorf("vault JWT/OIDC authentication requires SSO to be configured - no SSO token available")
	}

	// Validate auth config exists
	if cfg.Auth == nil {
		return fmt.Errorf("vault JWT/OIDC authentication requires 'auth' configuration")
	}

	// Validate role is provided
	if cfg.Auth.Role == "" {
		return fmt.Errorf("vault JWT/OIDC authentication requires 'auth.role' field in configuration")
	}

	// Determine auth mount path
	authMount := cfg.Auth.Mount
	if authMount == "" {
		authMount = DefaultJWTAuthMount
	}

	// Authenticate with Vault using JWT auth
	loginPath := fmt.Sprintf("auth/%s/login", authMount)
	loginData := map[string]interface{}{
		"role": cfg.Auth.Role,
		"jwt":  jwtToken,
	}

	secret, err := client.Logical().WriteWithContext(ctx, loginPath, loginData)
	if err != nil {
		return fmt.Errorf("vault JWT authentication failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("vault JWT authentication failed: no auth info returned")
	}

	// Set the client token from the auth response
	client.SetToken(secret.Auth.ClientToken)

	return nil
}

// parseConfig converts a map[string]interface{} to VaultConfig
func parseConfig(config map[string]interface{}) (*VaultConfig, error) {
	// Use JSON marshaling/unmarshaling for clean conversion
	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var cfg VaultConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Extract SSO tokens from the config map (these are injected by the collector)
	if accessToken, ok := config["_sso_access_token"].(string); ok {
		cfg.SSOAccessToken = accessToken
	}
	if idToken, ok := config["_sso_id_token"].(string); ok {
		cfg.SSOIDToken = idToken
	}

	// Support top-level 'token' field for backward compatibility with simpler configs
	// e.g., `token: my-token` instead of `auth: { method: token, token: my-token }`
	if token, ok := config["token"].(string); ok && token != "" {
		if cfg.Auth == nil {
			cfg.Auth = &VaultAuthConfig{}
		}
		// Only set if auth.token is not already set (explicit auth config takes precedence)
		if cfg.Auth.Token == "" {
			cfg.Auth.Token = token
		}
	}

	return &cfg, nil
}

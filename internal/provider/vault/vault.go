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

// VaultConfig represents the configuration for HashiCorp Vault provider
type VaultConfig struct {
	// Address is the Vault server address (optional, defaults to VAULT_ADDR env var)
	Address string `json:"address,omitempty" yaml:"address,omitempty"`
	// Token is the Vault authentication token (optional, defaults to VAULT_TOKEN env var)
	Token string `json:"token,omitempty" yaml:"token,omitempty"`
	// Path is the path to the secret in Vault (required)
	Path string `json:"path" yaml:"path"`
	// Mount is the secret engine mount path (optional, defaults to "secret")
	Mount string `json:"mount,omitempty" yaml:"mount,omitempty"`
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
func (p *VaultProvider) Fetch(ctx context.Context, mapID string, config map[string]interface{}, keys map[string]string) ([]provider.KeyValue, error) {
	// Convert map to strongly typed config struct
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid vault configuration: %w", err)
	}

	// Validate required fields
	if cfg.Path == "" {
		return nil, fmt.Errorf("vault provider requires 'path' field in configuration")
	}

	if err := p.ensureClient(cfg.Address, cfg.Token); err != nil {
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

func (p *VaultProvider) ensureClient(address, token string) error {
	if p.client != nil {
		return nil
	}

	// Create default config
	cfg := api.DefaultConfig()

	// Read environment variables first
	if err := cfg.ReadEnvironment(); err != nil {
		return fmt.Errorf("failed to read environment: %w", err)
	}

	// Override address if provided
	if address != "" {
		cfg.Address = address
	} else if cfg.Address == "" {
		// If VAULT_ADDR is not set, use default
		cfg.Address = "http://127.0.0.1:8200"
	}

	// Create client
	client, err := api.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

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
		return fmt.Errorf("vault authentication token is required (set 'token' in config or VAULT_TOKEN environment variable)")
	}

	p.client = client
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

	return &cfg, nil
}

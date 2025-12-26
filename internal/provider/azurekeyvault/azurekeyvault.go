package azurekeyvault

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/dirathea/sstart/internal/provider"
)

// AzureKeyVaultConfig represents the configuration for Azure Key Vault provider
type AzureKeyVaultConfig struct {
	// VaultURL is the URL of the Azure Key Vault (required)
	// Format: https://{vault-name}.vault.azure.net/ or custom endpoint for emulator
	VaultURL string `json:"vault_url" yaml:"vault_url"`
	// SecretName is the name of the secret in Azure Key Vault (required)
	SecretName string `json:"secret_name" yaml:"secret_name"`
	// Version is the secret version to fetch (optional, defaults to latest)
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
}

// AzureKeyVaultProvider implements the provider interface for Azure Key Vault
type AzureKeyVaultProvider struct {
	client *azsecrets.Client
}

func init() {
	provider.Register("azure_keyvault", func() provider.Provider {
		return &AzureKeyVaultProvider{}
	})
}

// Name returns the provider name
func (p *AzureKeyVaultProvider) Name() string {
	return "azure_keyvault"
}

// Fetch fetches secrets from Azure Key Vault
func (p *AzureKeyVaultProvider) Fetch(secretContext provider.SecretContext, mapID string, config map[string]interface{}, keys map[string]string) ([]provider.KeyValue, error) {
	ctx := secretContext.Ctx
	// Convert map to strongly typed config struct
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid azure_keyvault configuration: %w", err)
	}

	// Validate required fields
	if cfg.VaultURL == "" {
		return nil, fmt.Errorf("azure_keyvault provider requires 'vault_url' field in configuration")
	}
	if cfg.SecretName == "" {
		return nil, fmt.Errorf("azure_keyvault provider requires 'secret_name' field in configuration")
	}

	if err := p.ensureClient(ctx, cfg.VaultURL); err != nil {
		return nil, fmt.Errorf("failed to initialize Azure Key Vault client: %w", err)
	}

	// Determine version (default to empty string for latest)
	version := cfg.Version

	// Get the secret from Key Vault
	var resp azsecrets.GetSecretResponse
	if version != "" {
		resp, err = p.client.GetSecret(ctx, cfg.SecretName, version, nil)
	} else {
		resp, err = p.client.GetSecret(ctx, cfg.SecretName, "", nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secret from Azure Key Vault: %w", err)
	}

	// Get the secret value
	secretValue := ""
	if resp.Value != nil {
		secretValue = *resp.Value
	}

	if secretValue == "" {
		return nil, fmt.Errorf("secret '%s' has no value", cfg.SecretName)
	}

	// Try to parse as JSON first
	var secretData map[string]interface{}
	if err := json.Unmarshal([]byte(secretValue), &secretData); err != nil {
		// If not JSON, treat as a single value
		secretKey := strings.ToUpper(strings.ReplaceAll(mapID, "-", "_")) + "_SECRET"
		log.Printf("WARN: Secret from provider '%s' is not JSON format. Secret loaded to %s", mapID, secretKey)
		return []provider.KeyValue{
			{Key: secretKey, Value: secretValue},
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

func (p *AzureKeyVaultProvider) ensureClient(ctx context.Context, vaultURL string) error {
	if p.client != nil {
		return nil
	}

	// For emulator/local testing, use DefaultAzureCredential which will fall back to
	// various authentication methods. For emulator, we typically use environment variables
	// or managed identity, but for local testing with emulator, we can use DefaultAzureCredential
	// which will try to authenticate. For emulator, we might need to disable SSL verification.

	// Create credential - DefaultAzureCredential will try multiple authentication methods
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure credential: %w", err)
	}

	// Check if this is an emulator (localhost or lowkey-vault)
	isEmulator := strings.Contains(vaultURL, "localhost") ||
		strings.Contains(vaultURL, "127.0.0.1") ||
		strings.Contains(vaultURL, "lowkey-vault")

	// Configure client options
	var clientOptions *azsecrets.ClientOptions
	if isEmulator {
		// For emulators, configure TLS to skip certificate verification
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip certificate verification for emulator
			},
		}
		httpClient := &http.Client{
			Transport: transport,
		}

		clientOptions = &azsecrets.ClientOptions{
			ClientOptions: policy.ClientOptions{
				Transport: httpClient,
			},
			DisableChallengeResourceVerification: true, // Required for Lowkey Vault emulator
		}
	}

	// Create client
	client, err := azsecrets.NewClient(vaultURL, cred, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}

	p.client = client
	return nil
}

// parseConfig converts a map[string]interface{} to AzureKeyVaultConfig
func parseConfig(config map[string]interface{}) (*AzureKeyVaultConfig, error) {
	// Use JSON marshaling/unmarshaling for clean conversion
	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var cfg AzureKeyVaultConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

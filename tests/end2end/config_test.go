package end2end

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dirathea/sstart/internal/config"
	"github.com/dirathea/sstart/internal/provider"
	_ "github.com/dirathea/sstart/internal/provider/aws"
	_ "github.com/dirathea/sstart/internal/provider/dotenv"
	_ "github.com/dirathea/sstart/internal/provider/vault"
	"github.com/dirathea/sstart/internal/secrets"
)

// TestE2E_Config_AllProviders tests the full flow from YAML config to provider config parsing
func TestE2E_Config_AllProviders(t *testing.T) {
	tests := []struct {
		name           string
		yamlContent    string
		providerKind   string
		providerID     string
		expectedConfig map[string]interface{}
		validateFunc   func(t *testing.T, cfg map[string]interface{})
	}{
		{
			name: "Vault provider with all fields",
			yamlContent: `
providers:
  - kind: vault
    id: vault-test
    path: myapp/secret
    address: https://vault.example.com:8200
    mount: secret-v2
    auth:
      method: token
      token: test-token-123
`,
			providerKind: "vault",
			providerID:   "vault-test",
			validateFunc: func(t *testing.T, cfg map[string]interface{}) {
				if path, ok := cfg["path"].(string); !ok || path != "myapp/secret" {
					t.Errorf("expected path='myapp/secret', got %v", cfg["path"])
				}
				if address, ok := cfg["address"].(string); !ok || address != "https://vault.example.com:8200" {
					t.Errorf("expected address='https://vault.example.com:8200', got %v", cfg["address"])
				}
				if mount, ok := cfg["mount"].(string); !ok || mount != "secret-v2" {
					t.Errorf("expected mount='secret-v2', got %v", cfg["mount"])
				}
			},
		},
		{
			name: "Vault provider with only required path",
			yamlContent: `
providers:
  - kind: vault
    path: required/path
`,
			providerKind: "vault",
			providerID:   "vault",
			validateFunc: func(t *testing.T, cfg map[string]interface{}) {
				if path, ok := cfg["path"].(string); !ok || path != "required/path" {
					t.Errorf("expected path='required/path', got %v", cfg["path"])
				}
				// Optional fields should not be present or should be empty
				if address, exists := cfg["address"]; exists && address != "" {
					t.Errorf("address should not be set or should be empty, got %v", address)
				}
			},
		},
		{
			name: "AWS Secrets Manager with all fields",
			yamlContent: `
providers:
  - kind: aws_secretsmanager
    id: aws-test
    secret_id: myapp/production
    region: us-west-2
    endpoint: https://secretsmanager.us-west-2.amazonaws.com
`,
			providerKind: "aws_secretsmanager",
			providerID:   "aws-test",
			validateFunc: func(t *testing.T, cfg map[string]interface{}) {
				if secretID, ok := cfg["secret_id"].(string); !ok || secretID != "myapp/production" {
					t.Errorf("expected secret_id='myapp/production', got %v", cfg["secret_id"])
				}
				if region, ok := cfg["region"].(string); !ok || region != "us-west-2" {
					t.Errorf("expected region='us-west-2', got %v", cfg["region"])
				}
				if endpoint, ok := cfg["endpoint"].(string); !ok || endpoint != "https://secretsmanager.us-west-2.amazonaws.com" {
					t.Errorf("expected endpoint='https://secretsmanager.us-west-2.amazonaws.com', got %v", cfg["endpoint"])
				}
			},
		},
		{
			name: "AWS Secrets Manager with ARN and region",
			yamlContent: `
providers:
  - kind: aws_secretsmanager
    id: aws-arn
    secret_id: arn:aws:secretsmanager:us-east-1:123456789012:secret:myapp/secret-abc123
    region: us-east-1
`,
			providerKind: "aws_secretsmanager",
			providerID:   "aws-arn",
			validateFunc: func(t *testing.T, cfg map[string]interface{}) {
				expectedARN := "arn:aws:secretsmanager:us-east-1:123456789012:secret:myapp/secret-abc123"
				if secretID, ok := cfg["secret_id"].(string); !ok || secretID != expectedARN {
					t.Errorf("expected secret_id='%s', got %v", expectedARN, cfg["secret_id"])
				}
				if region, ok := cfg["region"].(string); !ok || region != "us-east-1" {
					t.Errorf("expected region='us-east-1', got %v", cfg["region"])
				}
			},
		},
		{
			name: "Dotenv provider with path",
			yamlContent: `
providers:
  - kind: dotenv
    id: dotenv-test
    path: .env.local
`,
			providerKind: "dotenv",
			providerID:   "dotenv-test",
			validateFunc: func(t *testing.T, cfg map[string]interface{}) {
				if path, ok := cfg["path"].(string); !ok || path != ".env.local" {
					t.Errorf("expected path='.env.local', got %v", cfg["path"])
				}
			},
		},
		{
			name: "Dotenv provider with environment variable in path",
			yamlContent: `
providers:
  - kind: dotenv
    path: ${HOME}/.config/myapp/.env
`,
			providerKind: "dotenv",
			providerID:   "dotenv",
			validateFunc: func(t *testing.T, cfg map[string]interface{}) {
				expectedPath := "${HOME}/.config/myapp/.env"
				if path, ok := cfg["path"].(string); !ok || path != expectedPath {
					t.Errorf("expected path='%s', got %v", expectedPath, cfg["path"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary YAML file
			tmpDir := t.TempDir()
			yamlFile := filepath.Join(tmpDir, "test.yml")
			if err := os.WriteFile(yamlFile, []byte(tt.yamlContent), 0644); err != nil {
				t.Fatalf("Failed to create test YAML file: %v", err)
			}

			// Load config from YAML
			cfg, err := config.Load(yamlFile)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			// Get provider config
			providerCfg, err := cfg.GetProvider(tt.providerID)
			if err != nil {
				t.Fatalf("Failed to get provider config: %v", err)
			}

			// Verify provider kind
			if providerCfg.Kind != tt.providerKind {
				t.Errorf("Expected kind='%s', got '%s'", tt.providerKind, providerCfg.Kind)
			}

			// Verify provider ID
			if providerCfg.ID != tt.providerID {
				t.Errorf("Expected ID='%s', got '%s'", tt.providerID, providerCfg.ID)
			}

			// Verify config map contains expected fields
			if tt.validateFunc != nil {
				tt.validateFunc(t, providerCfg.Config)
			}
		})
	}
}

// TestE2E_Config_ParseConfig tests that provider configs can be parsed after loading from YAML
func TestE2E_Config_ParseConfig(t *testing.T) {
	tests := []struct {
		name         string
		yamlContent  string
		providerKind string
		providerID   string
		testParse    func(t *testing.T, cfg map[string]interface{})
	}{
		{
			name: "Vault config parsing from YAML",
			yamlContent: `
providers:
  - kind: vault
    id: vault-parse
    path: test/path
    address: http://localhost:8200
    mount: kv
    auth:
      method: token
      token: dev-token
`,
			providerKind: "vault",
			providerID:   "vault-parse",
			testParse: func(t *testing.T, cfg map[string]interface{}) {
				// Test that Vault provider can parse this config
				// We can't test Fetch without a real Vault instance,
				// but we can verify the config structure is correct
				// by checking that parseConfig would work (tested indirectly via config structure)
				expectedFields := []string{"path", "address", "mount"}
				for _, field := range expectedFields {
					if _, exists := cfg[field]; !exists {
						t.Errorf("Expected field '%s' to be present in config", field)
					}
				}

				// Verify values
				if cfg["path"] != "test/path" {
					t.Errorf("path = %v, want 'test/path'", cfg["path"])
				}
				if cfg["address"] != "http://localhost:8200" {
					t.Errorf("address = %v, want 'http://localhost:8200'", cfg["address"])
				}
			},
		},
		{
			name: "AWS Secrets Manager config parsing from YAML",
			yamlContent: `
providers:
  - kind: aws_secretsmanager
    id: aws-parse
    secret_id: test/secret
    region: eu-west-1
    endpoint: http://localhost:4566
`,
			providerKind: "aws_secretsmanager",
			providerID:   "aws-parse",
			testParse: func(t *testing.T, cfg map[string]interface{}) {
				expectedFields := []string{"secret_id", "region", "endpoint"}
				for _, field := range expectedFields {
					if _, exists := cfg[field]; !exists {
						t.Errorf("Expected field '%s' to be present in config", field)
					}
				}

				if cfg["secret_id"] != "test/secret" {
					t.Errorf("secret_id = %v, want 'test/secret'", cfg["secret_id"])
				}
				if cfg["region"] != "eu-west-1" {
					t.Errorf("region = %v, want 'eu-west-1'", cfg["region"])
				}
			},
		},
		{
			name: "Dotenv config parsing from YAML",
			yamlContent: `
providers:
  - kind: dotenv
    id: dotenv-parse
    path: /absolute/path/to/.env
`,
			providerKind: "dotenv",
			providerID:   "dotenv-parse",
			testParse: func(t *testing.T, cfg map[string]interface{}) {
				if _, exists := cfg["path"]; !exists {
					t.Error("Expected field 'path' to be present in config")
				}

				if cfg["path"] != "/absolute/path/to/.env" {
					t.Errorf("path = %v, want '/absolute/path/to/.env'", cfg["path"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary YAML file
			tmpDir := t.TempDir()
			yamlFile := filepath.Join(tmpDir, "test.yml")
			if err := os.WriteFile(yamlFile, []byte(tt.yamlContent), 0644); err != nil {
				t.Fatalf("Failed to create test YAML file: %v", err)
			}

			// Load config
			cfg, err := config.Load(yamlFile)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			// Get provider config
			providerCfg, err := cfg.GetProvider(tt.providerID)
			if err != nil {
				t.Fatalf("Failed to get provider config: %v", err)
			}

			// Test that config can be parsed by provider
			if tt.testParse != nil {
				tt.testParse(t, providerCfg.Config)
			}
		})
	}
}

// TestE2E_Config_MultipleProviders tests YAML with multiple providers
func TestE2E_Config_MultipleProviders(t *testing.T) {
	yamlContent := `
providers:
  - kind: vault
    id: vault-prod
    path: prod/secret
    address: https://vault.prod.com
    auth:
      method: token
      token: prod-token
  
  - kind: aws_secretsmanager
    id: aws-prod
    secret_id: prod/secret
    region: us-east-1
  
  - kind: dotenv
    id: dotenv-local
    path: .env.local
  
  - kind: dotenv
    id: dotenv-shared
    path: .env.shared
`

	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "test.yml")
	if err := os.WriteFile(yamlFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to create test YAML file: %v", err)
	}

	// Load config
	cfg, err := config.Load(yamlFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify all providers are loaded
	if len(cfg.Providers) != 4 {
		t.Fatalf("Expected 4 providers, got %d", len(cfg.Providers))
	}

	// Test vault provider
	vaultCfg, err := cfg.GetProvider("vault-prod")
	if err != nil {
		t.Fatalf("Failed to get vault provider: %v", err)
	}
	if vaultCfg.Config["path"] != "prod/secret" {
		t.Errorf("vault path = %v, want 'prod/secret'", vaultCfg.Config["path"])
	}

	// Test AWS provider
	awsCfg, err := cfg.GetProvider("aws-prod")
	if err != nil {
		t.Fatalf("Failed to get aws provider: %v", err)
	}
	if awsCfg.Config["secret_id"] != "prod/secret" {
		t.Errorf("aws secret_id = %v, want 'prod/secret'", awsCfg.Config["secret_id"])
	}

	// Test dotenv providers
	dotenvLocalCfg, err := cfg.GetProvider("dotenv-local")
	if err != nil {
		t.Fatalf("Failed to get dotenv-local provider: %v", err)
	}
	if dotenvLocalCfg.Config["path"] != ".env.local" {
		t.Errorf("dotenv-local path = %v, want '.env.local'", dotenvLocalCfg.Config["path"])
	}

	dotenvSharedCfg, err := cfg.GetProvider("dotenv-shared")
	if err != nil {
		t.Fatalf("Failed to get dotenv-shared provider: %v", err)
	}
	if dotenvSharedCfg.Config["path"] != ".env.shared" {
		t.Errorf("dotenv-shared path = %v, want '.env.shared'", dotenvSharedCfg.Config["path"])
	}
}

// TestE2E_Config_ProviderSpecificFields tests that provider-specific fields are properly isolated
func TestE2E_Config_ProviderSpecificFields(t *testing.T) {
	yamlContent := `
providers:
  - kind: vault
    id: vault1
    path: secret1
    address: http://vault1:8200
  
  - kind: vault
    id: vault2
    path: secret2
    address: http://vault2:8200
    mount: kv-v2
  
  - kind: aws_secretsmanager
    id: aws1
    secret_id: secret1
    region: us-east-1
  
  - kind: aws_secretsmanager
    id: aws2
    secret_id: secret2
    region: us-west-2
    endpoint: http://localhost:4566
`

	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "test.yml")
	if err := os.WriteFile(yamlFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to create test YAML file: %v", err)
	}

	cfg, err := config.Load(yamlFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test that each provider has its own isolated config
	vault1, _ := cfg.GetProvider("vault1")
	vault2, _ := cfg.GetProvider("vault2")
	aws1, _ := cfg.GetProvider("aws1")
	aws2, _ := cfg.GetProvider("aws2")

	// Verify vault1 doesn't have vault2's mount
	if mount, exists := vault1.Config["mount"]; exists {
		t.Errorf("vault1 should not have mount field, got %v", mount)
	}

	// Verify vault2 has mount
	if mount := vault2.Config["mount"]; mount != "kv-v2" {
		t.Errorf("vault2 mount = %v, want 'kv-v2'", mount)
	}

	// Verify aws1 doesn't have aws2's endpoint
	if endpoint, exists := aws1.Config["endpoint"]; exists {
		t.Errorf("aws1 should not have endpoint field, got %v", endpoint)
	}

	// Verify aws2 has endpoint
	if endpoint := aws2.Config["endpoint"]; endpoint != "http://localhost:4566" {
		t.Errorf("aws2 endpoint = %v, want 'http://localhost:4566'", endpoint)
	}
}

// TestE2E_Config_WithKeys tests that keys mapping is properly extracted
func TestE2E_Config_WithKeys(t *testing.T) {
	yamlContent := `
providers:
  - kind: vault
    id: vault-keys
    path: secret
    keys:
      SOURCE_KEY: TARGET_KEY
      KEEP_SAME: ==
  
  - kind: aws_secretsmanager
    id: aws-keys
    secret_id: secret
    keys:
      API_KEY: ==
      DB_URL: DATABASE_URL
`

	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "test.yml")
	if err := os.WriteFile(yamlFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to create test YAML file: %v", err)
	}

	cfg, err := config.Load(yamlFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test vault keys
	vaultCfg, _ := cfg.GetProvider("vault-keys")
	if len(vaultCfg.Keys) != 2 {
		t.Fatalf("Expected 2 keys for vault, got %d", len(vaultCfg.Keys))
	}
	if vaultCfg.Keys["SOURCE_KEY"] != "TARGET_KEY" {
		t.Errorf("vault keys SOURCE_KEY = %v, want 'TARGET_KEY'", vaultCfg.Keys["SOURCE_KEY"])
	}
	if vaultCfg.Keys["KEEP_SAME"] != "==" {
		t.Errorf("vault keys KEEP_SAME = %v, want '=='", vaultCfg.Keys["KEEP_SAME"])
	}

	// Test aws keys
	awsCfg, _ := cfg.GetProvider("aws-keys")
	if len(awsCfg.Keys) != 2 {
		t.Fatalf("Expected 2 keys for aws, got %d", len(awsCfg.Keys))
	}
	if awsCfg.Keys["API_KEY"] != "==" {
		t.Errorf("aws keys API_KEY = %v, want '=='", awsCfg.Keys["API_KEY"])
	}
	if awsCfg.Keys["DB_URL"] != "DATABASE_URL" {
		t.Errorf("aws keys DB_URL = %v, want 'DATABASE_URL'", awsCfg.Keys["DB_URL"])
	}

	// Verify keys are not in Config map (they should be separate)
	if _, exists := vaultCfg.Config["keys"]; exists {
		t.Error("keys should not be in Config map")
	}
	if _, exists := awsCfg.Config["keys"]; exists {
		t.Error("keys should not be in Config map")
	}
}

// TestE2E_Config_ProviderParseConfig tests that providers can parse configs loaded from YAML
// This verifies the end-to-end flow: YAML -> Config -> Provider.Config -> Provider parsing
func TestE2E_Config_ProviderParseConfig(t *testing.T) {
	tests := []struct {
		name           string
		yamlContent    string
		providerKind   string
		providerID     string
		expectParseErr bool
		errorContains  string
	}{
		{
			name: "Vault provider can parse config from YAML",
			yamlContent: `
providers:
  - kind: vault
    id: vault-parse-test
    path: test/path
    address: http://localhost:8200
    mount: kv
    auth:
      method: token
      token: test-token
`,
			providerKind:   "vault",
			providerID:     "vault-parse-test",
			expectParseErr: true, // Will fail because we don't have a real Vault, but config parsing should work
			errorContains:  "",   // Connection/auth errors mean config was parsed successfully
		},
		{
			name: "AWS Secrets Manager can parse config from YAML",
			yamlContent: `
providers:
  - kind: aws_secretsmanager
    id: aws-parse-test
    secret_id: test/secret
    region: us-east-1
`,
			providerKind:   "aws_secretsmanager",
			providerID:     "aws-parse-test",
			expectParseErr: true, // Will fail because we don't have AWS credentials, but config parsing should work
			errorContains:  "",   // Error will be about AWS connection, not config parsing
		},
		{
			name: "Dotenv provider can parse config from YAML",
			yamlContent: `
providers:
  - kind: dotenv
    id: dotenv-parse-test
    path: /nonexistent/path/.env
`,
			providerKind:   "dotenv",
			providerID:     "dotenv-parse-test",
			expectParseErr: true,                       // Will fail because file doesn't exist, but config parsing should work
			errorContains:  "failed to read .env file", // Should fail at file reading, not config parsing
		},
		{
			name: "Vault provider missing required path",
			yamlContent: `
providers:
  - kind: vault
    id: vault-missing-path
    address: http://localhost:8200
`,
			providerKind:   "vault",
			providerID:     "vault-missing-path",
			expectParseErr: true,
			errorContains:  "vault provider requires 'path' field",
		},
		{
			name: "AWS Secrets Manager missing required secret_id",
			yamlContent: `
providers:
  - kind: aws_secretsmanager
    id: aws-missing-secret-id
    region: us-east-1
`,
			providerKind:   "aws_secretsmanager",
			providerID:     "aws-missing-secret-id",
			expectParseErr: true,
			errorContains:  "aws_secretsmanager provider requires 'secret_id' field",
		},
		{
			name: "Dotenv provider missing required path",
			yamlContent: `
providers:
  - kind: dotenv
    id: dotenv-missing-path
`,
			providerKind:   "dotenv",
			providerID:     "dotenv-missing-path",
			expectParseErr: true,
			errorContains:  "dotenv provider requires 'path' field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary YAML file
			tmpDir := t.TempDir()
			yamlFile := filepath.Join(tmpDir, "test.yml")
			if err := os.WriteFile(yamlFile, []byte(tt.yamlContent), 0644); err != nil {
				t.Fatalf("Failed to create test YAML file: %v", err)
			}

			// Load config from YAML
			cfg, err := config.Load(yamlFile)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			// Get provider config
			providerCfg, err := cfg.GetProvider(tt.providerID)
			if err != nil {
				t.Fatalf("Failed to get provider config: %v", err)
			}

			// Verify provider kind
			if providerCfg.Kind != tt.providerKind {
				t.Fatalf("Expected kind='%s', got '%s'", tt.providerKind, providerCfg.Kind)
			}

			// Create provider instance
			prov, err := provider.New(providerCfg.Kind)
			if err != nil {
				t.Fatalf("Failed to create provider: %v", err)
			}

			// Try to Fetch (will fail for missing connections/credentials, but config parsing should work)
			ctx := context.Background()
			secretContext := secrets.NewEmptySecretContext(ctx)
			_, err = prov.Fetch(secretContext, providerCfg.ID, providerCfg.Config, providerCfg.Keys)

			if (err != nil) != tt.expectParseErr {
				t.Errorf("Expected parse error: %v, got error: %v", tt.expectParseErr, err)
				return
			}

			// If we expect a parse error, verify it contains expected message (if specified)
			if tt.expectParseErr && err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
			}

			// The key verification is that config parsing didn't fail with a config parsing error
			// If it fails with connection/auth/file errors, that's expected and means config was parsed correctly
			if tt.expectParseErr && err != nil {
				// Check that error is NOT a config parsing error (these are bad)
				configParseErrors := []string{"invalid", "failed to unmarshal", "failed to marshal"}
				for _, parseErr := range configParseErrors {
					if strings.Contains(strings.ToLower(err.Error()), parseErr) && strings.Contains(strings.ToLower(err.Error()), "config") {
						t.Errorf("Config parsing failed (unexpected): %v", err)
						return
					}
				}
				// Connection/auth/file errors mean config was parsed successfully
				// This is the success case for config parsing
			}
		})
	}
}

// TestE2E_Config_SSOConfig_Load tests that SSO configuration can be loaded from YAML
func TestE2E_Config_SSOConfig_Load(t *testing.T) {
	tests := []struct {
		name          string
		yamlContent   string
		expectError   bool
		errorContains string
		validateFunc  func(t *testing.T, cfg *config.Config)
	}{
		{
			name: "SSO config with full OIDC configuration",
			yamlContent: `
sso:
  oidc:
    clientId: my-sso-client-id
    issuer: https://example.com/oidc
    scopes:
      - openid
      - profile
      - email
`,
			expectError: false,
			validateFunc: func(t *testing.T, cfg *config.Config) {
				if cfg.SSO == nil {
					t.Fatal("expected SSO config to be set")
				}
				if cfg.SSO.OIDC == nil {
					t.Fatal("expected OIDC config to be set")
				}
				if cfg.SSO.OIDC.ClientID != "my-sso-client-id" {
					t.Errorf("expected ClientID='my-sso-client-id', got '%s'", cfg.SSO.OIDC.ClientID)
				}
				if cfg.SSO.OIDC.Issuer != "https://example.com/oidc" {
					t.Errorf("expected Issuer='https://example.com/oidc', got '%s'", cfg.SSO.OIDC.Issuer)
				}
				expectedScopes := []string{"openid", "profile", "email"}
				if len(cfg.SSO.OIDC.Scopes) != len(expectedScopes) {
					t.Errorf("expected %d scopes, got %d", len(expectedScopes), len(cfg.SSO.OIDC.Scopes))
				}
				for i, scope := range expectedScopes {
					if cfg.SSO.OIDC.Scopes[i] != scope {
						t.Errorf("expected scope[%d]='%s', got '%s'", i, scope, cfg.SSO.OIDC.Scopes[i])
					}
				}
			},
		},
		{
			name: "SSO config with scopes as space-separated string",
			yamlContent: `
sso:
  oidc:
    clientId: my-sso-client-id
    issuer: https://example.com/oidc
    scopes: openid profile email
`,
			expectError: false,
			validateFunc: func(t *testing.T, cfg *config.Config) {
				if cfg.SSO.OIDC == nil {
					t.Fatal("expected OIDC config to be set")
				}
				expectedScopes := []string{"openid", "profile", "email"}
				if len(cfg.SSO.OIDC.Scopes) != len(expectedScopes) {
					t.Errorf("expected %d scopes, got %d", len(expectedScopes), len(cfg.SSO.OIDC.Scopes))
				}
				for i, scope := range expectedScopes {
					if cfg.SSO.OIDC.Scopes[i] != scope {
						t.Errorf("expected scope[%d]='%s', got '%s'", i, scope, cfg.SSO.OIDC.Scopes[i])
					}
				}
			},
		},
		{
			name: "SSO config with clientSecret (no PKCE)",
			yamlContent: `
sso:
  oidc:
    clientId: my-sso-client-id
    issuer: https://example.com/oidc
    scopes:
      - openid
      - profile
`,
			expectError: false,
			validateFunc: func(t *testing.T, cfg *config.Config) {
				// ClientSecret is intentionally NOT parsed from YAML for security reasons.
				// It must be provided via the SSTART_SSO_SECRET environment variable.
				// This test verifies the config loads correctly without clientSecret in YAML.
				if cfg.SSO.OIDC.ClientSecret != "" {
					t.Errorf("expected ClientSecret to be empty (must be set via env var, not YAML), got '%s'", cfg.SSO.OIDC.ClientSecret)
				}
			},
		},
		{
			name: "SSO config with PKCE explicitly enabled",
			yamlContent: `
sso:
  oidc:
    clientId: my-sso-client-id
    issuer: https://example.com/oidc
    scopes:
      - openid
    pkce: true
`,
			expectError: false,
			validateFunc: func(t *testing.T, cfg *config.Config) {
				if cfg.SSO.OIDC.PKCE == nil {
					t.Error("expected PKCE to be set")
				} else if !*cfg.SSO.OIDC.PKCE {
					t.Error("expected PKCE to be true")
				}
			},
		},
		{
			name: "SSO config with redirectURI",
			yamlContent: `
sso:
  oidc:
    clientId: my-sso-client-id
    issuer: https://example.com/oidc
    scopes:
      - openid
    redirectUri: http://localhost:8080/auth/callback
`,
			expectError: false,
			validateFunc: func(t *testing.T, cfg *config.Config) {
				expectedURI := "http://localhost:8080/auth/callback"
				if cfg.SSO.OIDC.RedirectURI != expectedURI {
					t.Errorf("expected RedirectURI='%s', got '%s'", expectedURI, cfg.SSO.OIDC.RedirectURI)
				}
			},
		},
		{
			name: "SSO config with responseMode",
			yamlContent: `
sso:
  oidc:
    clientId: my-sso-client-id
    issuer: https://example.com/oidc
    scopes:
      - openid
    responseMode: query
`,
			expectError: false,
			validateFunc: func(t *testing.T, cfg *config.Config) {
				if cfg.SSO.OIDC.ResponseMode != "query" {
					t.Errorf("expected ResponseMode='query', got '%s'", cfg.SSO.OIDC.ResponseMode)
				}
			},
		},
		{
			name: "Config without SSO",
			yamlContent: `
providers:
  - kind: dotenv
    path: .env
`,
			expectError: false,
			validateFunc: func(t *testing.T, cfg *config.Config) {
				if cfg.SSO != nil {
					t.Error("expected SSO config to be nil when not specified")
				}
			},
		},
		{
			name: "Config with SSO but no OIDC",
			yamlContent: `
sso: {}
providers:
  - kind: dotenv
    path: .env
`,
			expectError: false,
			validateFunc: func(t *testing.T, cfg *config.Config) {
				if cfg.SSO == nil {
					t.Fatal("expected SSO config to be set")
				}
				if cfg.SSO.OIDC != nil {
					t.Error("expected OIDC config to be nil when not specified")
				}
			},
		},
		{
			name: "SSO config missing required clientId",
			yamlContent: `
sso:
  oidc:
    issuer: https://example.com/oidc
    scopes:
      - openid
`,
			expectError:   true,
			errorContains: "sso.oidc.clientId is required",
		},
		{
			name: "SSO config missing required issuer",
			yamlContent: `
sso:
  oidc:
    clientId: my-sso-client-id
    scopes:
      - openid
`,
			expectError:   true,
			errorContains: "sso.oidc.issuer is required",
		},
		{
			name: "SSO config missing required scopes",
			yamlContent: `
sso:
  oidc:
    clientId: my-sso-client-id
    issuer: https://example.com/oidc
`,
			expectError:   true,
			errorContains: "sso.oidc.scopes is required",
		},
		{
			name: "SSO config with empty scopes array",
			yamlContent: `
sso:
  oidc:
    clientId: my-sso-client-id
    issuer: https://example.com/oidc
    scopes: []
`,
			expectError:   true,
			errorContains: "sso.oidc.scopes is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary YAML file
			tmpDir := t.TempDir()
			yamlFile := filepath.Join(tmpDir, "test.yml")
			if err := os.WriteFile(yamlFile, []byte(tt.yamlContent), 0644); err != nil {
				t.Fatalf("Failed to create test YAML file: %v", err)
			}

			// Load config
			cfg, err := config.Load(yamlFile)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain '%s', got: %v", tt.errorContains, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			// Validate
			if tt.validateFunc != nil {
				tt.validateFunc(t, cfg)
			}
		})
	}
}

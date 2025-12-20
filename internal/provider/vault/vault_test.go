package vault

import (
	"context"
	"testing"
)

func TestParseConfigWithAuthOptions(t *testing.T) {
	tests := []struct {
		name          string
		config        map[string]interface{}
		wantAuth      string
		wantAuthMount string
		wantRole      string
		wantErr       bool
	}{
		{
			name: "config with token auth (default)",
			config: map[string]interface{}{
				"path": "myapp/secret",
			},
			wantAuth:      "",
			wantAuthMount: "",
			wantRole:      "",
			wantErr:       false,
		},
		{
			name: "config with explicit token auth",
			config: map[string]interface{}{
				"path": "myapp/secret",
				"auth": "token",
			},
			wantAuth:      "token",
			wantAuthMount: "",
			wantRole:      "",
			wantErr:       false,
		},
		{
			name: "config with oidc auth",
			config: map[string]interface{}{
				"path": "myapp/secret",
				"auth": "oidc",
				"role": "my-role",
			},
			wantAuth:      "oidc",
			wantAuthMount: "",
			wantRole:      "my-role",
			wantErr:       false,
		},
		{
			name: "config with jwt auth and custom mount",
			config: map[string]interface{}{
				"path":      "myapp/secret",
				"auth":      "jwt",
				"authMount": "custom-jwt",
				"role":      "app-role",
			},
			wantAuth:      "jwt",
			wantAuthMount: "custom-jwt",
			wantRole:      "app-role",
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if cfg.Auth != tt.wantAuth {
				t.Errorf("parseConfig() Auth = %v, want %v", cfg.Auth, tt.wantAuth)
			}
			if cfg.AuthMount != tt.wantAuthMount {
				t.Errorf("parseConfig() AuthMount = %v, want %v", cfg.AuthMount, tt.wantAuthMount)
			}
			if cfg.Role != tt.wantRole {
				t.Errorf("parseConfig() Role = %v, want %v", cfg.Role, tt.wantRole)
			}
		})
	}
}

func TestParseConfigWithSSOTokens(t *testing.T) {
	config := map[string]interface{}{
		"path":              "myapp/secret",
		"auth":              "oidc",
		"role":              "my-role",
		"_sso_access_token": "test-access-token-123",
		"_sso_id_token":     "test-id-token-456",
	}

	cfg, err := parseConfig(config)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	if cfg.SSOAccessToken != "test-access-token-123" {
		t.Errorf("parseConfig() SSOAccessToken = %v, want %v", cfg.SSOAccessToken, "test-access-token-123")
	}
	if cfg.SSOIDToken != "test-id-token-456" {
		t.Errorf("parseConfig() SSOIDToken = %v, want %v", cfg.SSOIDToken, "test-id-token-456")
	}
}

func TestVaultProvider_Fetch_OIDCAuthValidation(t *testing.T) {
	provider := &VaultProvider{}

	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "oidc auth without role",
			config: map[string]interface{}{
				"path":              "myapp/secret",
				"auth":              "oidc",
				"_sso_access_token": "test-token",
			},
			wantErr: true,
			errMsg:  "requires 'role' field",
		},
		{
			name: "oidc auth without SSO token",
			config: map[string]interface{}{
				"path": "myapp/secret",
				"auth": "oidc",
				"role": "my-role",
			},
			wantErr: true,
			errMsg:  "no SSO token available",
		},
		{
			name: "jwt auth without role",
			config: map[string]interface{}{
				"path":          "myapp/secret",
				"auth":          "jwt",
				"_sso_id_token": "test-token",
			},
			wantErr: true,
			errMsg:  "requires 'role' field",
		},
		{
			name: "unsupported auth method",
			config: map[string]interface{}{
				"path": "myapp/secret",
				"auth": "invalid-method",
			},
			wantErr: true,
			errMsg:  "unsupported auth method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := provider.Fetch(ctx, "test-map", tt.config, nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("VaultProvider.Fetch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil {
				if tt.errMsg != "" && err.Error() != "" {
					if !containsSubstring(err.Error(), tt.errMsg) {
						t.Errorf("VaultProvider.Fetch() error = %v, want error containing %v", err.Error(), tt.errMsg)
					}
				}
			}
		})
	}
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]interface{}
		wantPath    string
		wantAddress string
		wantToken   string
		wantMount   string
		wantErr     bool
	}{
		{
			name: "valid config with all fields",
			config: map[string]interface{}{
				"path":    "myapp/secret",
				"address": "https://vault.example.com:8200",
				"token":   "test-token",
				"mount":   "secret-v2",
			},
			wantPath:    "myapp/secret",
			wantAddress: "https://vault.example.com:8200",
			wantToken:   "test-token",
			wantMount:   "secret-v2",
			wantErr:     false,
		},
		{
			name: "valid config with only required path",
			config: map[string]interface{}{
				"path": "myapp/secret",
			},
			wantPath:    "myapp/secret",
			wantAddress: "",
			wantToken:   "",
			wantMount:   "",
			wantErr:     false,
		},
		{
			name: "valid config with address and token",
			config: map[string]interface{}{
				"path":    "myapp/secret",
				"address": "http://localhost:8200",
				"token":   "dev-token",
			},
			wantPath:    "myapp/secret",
			wantAddress: "http://localhost:8200",
			wantToken:   "dev-token",
			wantMount:   "",
			wantErr:     false,
		},
		{
			name: "valid config with custom mount",
			config: map[string]interface{}{
				"path":  "myapp/secret",
				"mount": "custom-mount",
			},
			wantPath:  "myapp/secret",
			wantMount: "custom-mount",
			wantErr:   false,
		},
		{
			name: "config with empty path",
			config: map[string]interface{}{
				"path": "",
			},
			wantPath:    "",
			wantAddress: "",
			wantToken:   "",
			wantMount:   "",
			wantErr:     false, // parseConfig doesn't validate, Fetch does
		},
		{
			name: "config with missing path field but has address",
			config: map[string]interface{}{
				"address": "https://vault.example.com",
			},
			wantPath:    "",
			wantAddress: "https://vault.example.com",
			wantErr:     false, // parseConfig doesn't validate, Fetch does
		},
		{
			name: "config with numeric path",
			config: map[string]interface{}{
				"path": 123,
			},
			wantErr: true, // parseConfig validates types and will error for wrong type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if cfg.Path != tt.wantPath {
				t.Errorf("parseConfig() Path = %v, want %v", cfg.Path, tt.wantPath)
			}
			if cfg.Address != tt.wantAddress {
				t.Errorf("parseConfig() Address = %v, want %v", cfg.Address, tt.wantAddress)
			}
			if cfg.Token != tt.wantToken {
				t.Errorf("parseConfig() Token = %v, want %v", cfg.Token, tt.wantToken)
			}
			if cfg.Mount != tt.wantMount {
				t.Errorf("parseConfig() Mount = %v, want %v", cfg.Mount, tt.wantMount)
			}
		})
	}
}

func TestVaultProvider_Fetch_ConfigValidation(t *testing.T) {
	provider := &VaultProvider{}

	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "missing path field",
			config: map[string]interface{}{
				"address": "https://vault.example.com",
			},
			wantErr: true,
			errMsg:  "vault provider requires 'path' field",
		},
		{
			name: "empty path field",
			config: map[string]interface{}{
				"path": "",
			},
			wantErr: true,
			errMsg:  "vault provider requires 'path' field",
		},
		{
			name: "valid path but no token",
			config: map[string]interface{}{
				"path": "myapp/secret",
			},
			wantErr: true,
			errMsg:  "vault authentication token is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := provider.Fetch(ctx, "test-map", tt.config, nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("VaultProvider.Fetch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil {
				if tt.errMsg != "" && err.Error() != "" {
					// Check if error message contains expected substring
					if !containsSubstring(err.Error(), tt.errMsg) {
						t.Errorf("VaultProvider.Fetch() error = %v, want error containing %v", err.Error(), tt.errMsg)
					}
				}
			}
		})
	}
}

func TestVaultProvider_Name(t *testing.T) {
	provider := &VaultProvider{}
	if got := provider.Name(); got != "vault" {
		t.Errorf("VaultProvider.Name() = %v, want %v", got, "vault")
	}
}

func TestVaultProvider_ConfigFields(t *testing.T) {
	// Test that all config fields are properly parsed and accessible
	config := map[string]interface{}{
		"path":    "test/path",
		"address": "https://custom-vault.example.com:8200",
		"token":   "custom-token-123",
		"mount":   "custom-secret-engine",
	}

	cfg, err := parseConfig(config)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	if cfg.Path != "test/path" {
		t.Errorf("Config.Path = %v, want %v", cfg.Path, "test/path")
	}
	if cfg.Address != "https://custom-vault.example.com:8200" {
		t.Errorf("Config.Address = %v, want %v", cfg.Address, "https://custom-vault.example.com:8200")
	}
	if cfg.Token != "custom-token-123" {
		t.Errorf("Config.Token = %v, want %v", cfg.Token, "custom-token-123")
	}
	if cfg.Mount != "custom-secret-engine" {
		t.Errorf("Config.Mount = %v, want %v", cfg.Mount, "custom-secret-engine")
	}
}

func TestVaultProvider_ConfigWithOptionalFields(t *testing.T) {
	// Test that optional fields can be omitted
	config := map[string]interface{}{
		"path": "required/path",
	}

	cfg, err := parseConfig(config)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	if cfg.Path != "required/path" {
		t.Errorf("Config.Path = %v, want %v", cfg.Path, "required/path")
	}
	if cfg.Address != "" {
		t.Errorf("Config.Address = %v, want empty string", cfg.Address)
	}
	if cfg.Token != "" {
		t.Errorf("Config.Token = %v, want empty string", cfg.Token)
	}
	if cfg.Mount != "" {
		t.Errorf("Config.Mount = %v, want empty string", cfg.Mount)
	}
}

func TestVaultProvider_ConfigWithExtraFields(t *testing.T) {
	// Test that extra unknown fields don't break parsing
	config := map[string]interface{}{
		"path":    "test/path",
		"address": "https://vault.example.com",
		"unknown": "field",
		"extra":   123,
	}

	cfg, err := parseConfig(config)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	// Should still parse known fields correctly
	if cfg.Path != "test/path" {
		t.Errorf("Config.Path = %v, want %v", cfg.Path, "test/path")
	}
	if cfg.Address != "https://vault.example.com" {
		t.Errorf("Config.Address = %v, want %v", cfg.Address, "https://vault.example.com")
	}
}

// Helper function to check if a string contains a substring
func containsSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}


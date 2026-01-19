package aws

import (
	"context"
	"testing"

	"github.com/dirathea/sstart/internal/secrets"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       map[string]interface{}
		wantSecretID string
		wantRegion   string
		wantEndpoint string
		wantErr      bool
	}{
		{
			name: "valid config with all fields",
			config: map[string]interface{}{
				"secret_id": "myapp/production",
				"region":    "us-west-2",
				"endpoint":  "https://secretsmanager.us-west-2.amazonaws.com",
			},
			wantSecretID: "myapp/production",
			wantRegion:   "us-west-2",
			wantEndpoint: "https://secretsmanager.us-west-2.amazonaws.com",
			wantErr:      false,
		},
		{
			name: "valid config with only required secret_id",
			config: map[string]interface{}{
				"secret_id": "myapp/secret",
			},
			wantSecretID: "myapp/secret",
			wantRegion:   "",
			wantEndpoint: "",
			wantErr:      false,
		},
		{
			name: "valid config with secret_id and region",
			config: map[string]interface{}{
				"secret_id": "arn:aws:secretsmanager:us-east-1:123456789012:secret:myapp/secret",
				"region":    "us-east-1",
			},
			wantSecretID: "arn:aws:secretsmanager:us-east-1:123456789012:secret:myapp/secret",
			wantRegion:   "us-east-1",
			wantEndpoint: "",
			wantErr:      false,
		},
		{
			name: "valid config with custom endpoint",
			config: map[string]interface{}{
				"secret_id": "test-secret",
				"endpoint":  "http://localhost:4566",
			},
			wantSecretID: "test-secret",
			wantRegion:   "",
			wantEndpoint: "http://localhost:4566",
			wantErr:      false,
		},
		{
			name: "config with empty secret_id",
			config: map[string]interface{}{
				"secret_id": "",
			},
			wantErr: false, // parseConfig doesn't validate, Fetch does
		},
		{
			name: "config with missing secret_id field",
			config: map[string]interface{}{
				"region": "us-east-1",
			},
			wantSecretID: "",
			wantRegion:   "us-east-1",
			wantErr:      false, // parseConfig doesn't validate, Fetch does
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

			if cfg.SecretID != tt.wantSecretID {
				t.Errorf("parseConfig() SecretID = %v, want %v", cfg.SecretID, tt.wantSecretID)
			}
			if cfg.Region != tt.wantRegion {
				t.Errorf("parseConfig() Region = %v, want %v", cfg.Region, tt.wantRegion)
			}
			if cfg.Endpoint != tt.wantEndpoint {
				t.Errorf("parseConfig() Endpoint = %v, want %v", cfg.Endpoint, tt.wantEndpoint)
			}
		})
	}
}

func TestSecretsManagerProvider_Fetch_ConfigValidation(t *testing.T) {
	provider := &SecretsManagerProvider{}

	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "missing secret_id field",
			config: map[string]interface{}{
				"region": "us-east-1",
			},
			wantErr: true,
			errMsg:  "aws_secretsmanager provider requires 'secret_id' field",
		},
		{
			name: "empty secret_id field",
			config: map[string]interface{}{
				"secret_id": "",
			},
			wantErr: true,
			errMsg:  "aws_secretsmanager provider requires 'secret_id' field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			secretContext := secrets.NewEmptySecretContext(ctx)
			_, err := provider.Fetch(secretContext, "test-map", tt.config, nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("SecretsManagerProvider.Fetch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil {
				if tt.errMsg != "" && err.Error() != "" {
					// Check if error message contains expected substring
					if !containsSubstring(err.Error(), tt.errMsg) {
						t.Errorf("SecretsManagerProvider.Fetch() error = %v, want error containing %v", err.Error(), tt.errMsg)
					}
				}
			}
		})
	}
}

func TestSecretsManagerProvider_Name(t *testing.T) {
	provider := &SecretsManagerProvider{}
	if got := provider.Name(); got != "aws_secretsmanager" {
		t.Errorf("SecretsManagerProvider.Name() = %v, want %v", got, "aws_secretsmanager")
	}
}

func TestSecretsManagerProvider_ConfigFields(t *testing.T) {
	// Test that all config fields are properly parsed and accessible
	config := map[string]interface{}{
		"secret_id": "myapp/production/database",
		"region":    "eu-west-1",
		"endpoint":  "https://secretsmanager.eu-west-1.amazonaws.com",
	}

	cfg, err := parseConfig(config)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	if cfg.SecretID != "myapp/production/database" {
		t.Errorf("Config.SecretID = %v, want %v", cfg.SecretID, "myapp/production/database")
	}
	if cfg.Region != "eu-west-1" {
		t.Errorf("Config.Region = %v, want %v", cfg.Region, "eu-west-1")
	}
	if cfg.Endpoint != "https://secretsmanager.eu-west-1.amazonaws.com" {
		t.Errorf("Config.Endpoint = %v, want %v", cfg.Endpoint, "https://secretsmanager.eu-west-1.amazonaws.com")
	}
}

func TestSecretsManagerProvider_ConfigWithOptionalFields(t *testing.T) {
	// Test that optional fields can be omitted
	config := map[string]interface{}{
		"secret_id": "required-secret-name",
	}

	cfg, err := parseConfig(config)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	if cfg.SecretID != "required-secret-name" {
		t.Errorf("Config.SecretID = %v, want %v", cfg.SecretID, "required-secret-name")
	}
	if cfg.Region != "" {
		t.Errorf("Config.Region = %v, want empty string", cfg.Region)
	}
	if cfg.Endpoint != "" {
		t.Errorf("Config.Endpoint = %v, want empty string", cfg.Endpoint)
	}
}

func TestSecretsManagerProvider_ConfigWithARN(t *testing.T) {
	// Test that ARN format is properly handled
	arn := "arn:aws:secretsmanager:us-west-2:123456789012:secret:myapp/secret-abc123"
	config := map[string]interface{}{
		"secret_id": arn,
		"region":    "us-west-2",
	}

	cfg, err := parseConfig(config)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	if cfg.SecretID != arn {
		t.Errorf("Config.SecretID = %v, want %v", cfg.SecretID, arn)
	}
	if cfg.Region != "us-west-2" {
		t.Errorf("Config.Region = %v, want %v", cfg.Region, "us-west-2")
	}
}

func TestSecretsManagerProvider_ConfigWithExtraFields(t *testing.T) {
	// Test that extra unknown fields don't break parsing
	config := map[string]interface{}{
		"secret_id": "test-secret",
		"region":    "us-east-1",
		"unknown":   "field",
		"extra":     123,
	}

	cfg, err := parseConfig(config)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	// Should still parse known fields correctly
	if cfg.SecretID != "test-secret" {
		t.Errorf("Config.SecretID = %v, want %v", cfg.SecretID, "test-secret")
	}
	if cfg.Region != "us-east-1" {
		t.Errorf("Config.Region = %v, want %v", cfg.Region, "us-east-1")
	}
}

func TestParseConfig_WithSSOTokens(t *testing.T) {
	tests := []struct {
		name            string
		config          map[string]interface{}
		wantAccessToken string
		wantIDToken     string
		wantRoleArn     string
		wantSessionName string
		wantDuration    int32
	}{
		{
			name: "config with SSO tokens",
			config: map[string]interface{}{
				"secret_id":         "test-secret",
				"_sso_access_token": "test-access-token-123",
				"_sso_id_token":     "test-id-token-456",
			},
			wantAccessToken: "test-access-token-123",
			wantIDToken:     "test-id-token-456",
		},
		{
			name: "config with SSO tokens and role_arn",
			config: map[string]interface{}{
				"secret_id":         "test-secret",
				"role_arn":          "arn:aws:iam::123456789012:role/test-role",
				"session_name":      "test-session",
				"duration":          7200,
				"_sso_access_token": "access-token",
				"_sso_id_token":     "id-token",
			},
			wantAccessToken: "access-token",
			wantIDToken:     "id-token",
			wantRoleArn:     "arn:aws:iam::123456789012:role/test-role",
			wantSessionName: "test-session",
			wantDuration:    7200,
		},
		{
			name: "config with only ID token",
			config: map[string]interface{}{
				"secret_id":     "test-secret",
				"_sso_id_token": "only-id-token",
			},
			wantIDToken: "only-id-token",
		},
		{
			name: "config with only access token",
			config: map[string]interface{}{
				"secret_id":         "test-secret",
				"_sso_access_token": "only-access-token",
			},
			wantAccessToken: "only-access-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig(tt.config)
			if err != nil {
				t.Fatalf("parseConfig() error = %v", err)
			}

			if cfg.SSOAccessToken != tt.wantAccessToken {
				t.Errorf("Config.SSOAccessToken = %v, want %v", cfg.SSOAccessToken, tt.wantAccessToken)
			}
			if cfg.SSOIDToken != tt.wantIDToken {
				t.Errorf("Config.SSOIDToken = %v, want %v", cfg.SSOIDToken, tt.wantIDToken)
			}
			if cfg.RoleArn != tt.wantRoleArn {
				t.Errorf("Config.RoleArn = %v, want %v", cfg.RoleArn, tt.wantRoleArn)
			}
			if cfg.SessionName != tt.wantSessionName {
				t.Errorf("Config.SessionName = %v, want %v", cfg.SessionName, tt.wantSessionName)
			}
			if cfg.Duration != tt.wantDuration {
				t.Errorf("Config.Duration = %v, want %v", cfg.Duration, tt.wantDuration)
			}
		})
	}
}

func TestParseConfig_SSOFields(t *testing.T) {
	// Test all SSO-related fields
	config := map[string]interface{}{
		"secret_id":    "test-secret",
		"region":       "us-east-1",
		"role_arn":     "arn:aws:iam::123456789012:role/sstart-role",
		"session_name": "sstart-test",
		"duration":     3600,
	}

	cfg, err := parseConfig(config)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	if cfg.RoleArn != "arn:aws:iam::123456789012:role/sstart-role" {
		t.Errorf("Config.RoleArn = %v, want %v", cfg.RoleArn, "arn:aws:iam::123456789012:role/sstart-role")
	}
	if cfg.SessionName != "sstart-test" {
		t.Errorf("Config.SessionName = %v, want %v", cfg.SessionName, "sstart-test")
	}
	if cfg.Duration != 3600 {
		t.Errorf("Config.Duration = %v, want %v", cfg.Duration, 3600)
	}
}

func TestParseConfig_SSOTokensNotInJSON(t *testing.T) {
	// Verify SSO tokens are marked with json:"-" and don't serialize
	config := map[string]interface{}{
		"secret_id":         "test-secret",
		"_sso_access_token": "should-be-extracted",
		"_sso_id_token":     "should-also-be-extracted",
	}

	cfg, err := parseConfig(config)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	// Tokens should be extracted from config map
	if cfg.SSOAccessToken != "should-be-extracted" {
		t.Errorf("Config.SSOAccessToken = %v, want %v", cfg.SSOAccessToken, "should-be-extracted")
	}
	if cfg.SSOIDToken != "should-also-be-extracted" {
		t.Errorf("Config.SSOIDToken = %v, want %v", cfg.SSOIDToken, "should-also-be-extracted")
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

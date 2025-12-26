package gcsm

import (
	"context"
	"testing"

	"github.com/dirathea/sstart/internal/secrets"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        map[string]interface{}
		wantProjectID string
		wantSecretID  string
		wantVersion   string
		wantEndpoint  string
		wantErr       bool
	}{
		{
			name: "valid config with all fields",
			config: map[string]interface{}{
				"project_id": "my-project",
				"secret_id":  "my-secret",
				"version":    "1",
				"endpoint":   "http://localhost:8080",
			},
			wantProjectID: "my-project",
			wantSecretID:  "my-secret",
			wantVersion:   "1",
			wantEndpoint:  "http://localhost:8080",
			wantErr:       false,
		},
		{
			name: "valid config with only required fields",
			config: map[string]interface{}{
				"project_id": "my-project",
				"secret_id":  "my-secret",
			},
			wantProjectID: "my-project",
			wantSecretID:  "my-secret",
			wantVersion:   "",
			wantEndpoint:  "",
			wantErr:       false,
		},
		{
			name: "valid config with project_id, secret_id and version",
			config: map[string]interface{}{
				"project_id": "test-project",
				"secret_id":  "test-secret",
				"version":    "latest",
			},
			wantProjectID: "test-project",
			wantSecretID:  "test-secret",
			wantVersion:   "latest",
			wantEndpoint:  "",
			wantErr:       false,
		},
		{
			name: "valid config with custom endpoint",
			config: map[string]interface{}{
				"project_id": "test-project",
				"secret_id":  "test-secret",
				"endpoint":   "http://localhost:8080",
			},
			wantProjectID: "test-project",
			wantSecretID:  "test-secret",
			wantVersion:   "",
			wantEndpoint:  "http://localhost:8080",
			wantErr:       false,
		},
		{
			name: "config with empty project_id",
			config: map[string]interface{}{
				"project_id": "",
				"secret_id":  "my-secret",
			},
			wantErr: false, // parseConfig doesn't validate, Fetch does
		},
		{
			name: "config with missing project_id field",
			config: map[string]interface{}{
				"secret_id": "my-secret",
			},
			wantProjectID: "",
			wantSecretID:  "my-secret",
			wantErr:       false, // parseConfig doesn't validate, Fetch does
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

			if cfg.ProjectID != tt.wantProjectID {
				t.Errorf("parseConfig() ProjectID = %v, want %v", cfg.ProjectID, tt.wantProjectID)
			}
			if cfg.SecretID != tt.wantSecretID {
				t.Errorf("parseConfig() SecretID = %v, want %v", cfg.SecretID, tt.wantSecretID)
			}
			if cfg.Version != tt.wantVersion {
				t.Errorf("parseConfig() Version = %v, want %v", cfg.Version, tt.wantVersion)
			}
			if cfg.Endpoint != tt.wantEndpoint {
				t.Errorf("parseConfig() Endpoint = %v, want %v", cfg.Endpoint, tt.wantEndpoint)
			}
		})
	}
}

func TestGCSMProvider_Fetch_ConfigValidation(t *testing.T) {
	provider := &GCSMProvider{}

	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "missing project_id field",
			config: map[string]interface{}{
				"secret_id": "my-secret",
			},
			wantErr: true,
			errMsg:  "gcloud_secretmanager provider requires 'project_id' field",
		},
		{
			name: "missing secret_id field",
			config: map[string]interface{}{
				"project_id": "my-project",
			},
			wantErr: true,
			errMsg:  "gcloud_secretmanager provider requires 'secret_id' field",
		},
		{
			name: "empty project_id field",
			config: map[string]interface{}{
				"project_id": "",
				"secret_id":  "my-secret",
			},
			wantErr: true,
			errMsg:  "gcloud_secretmanager provider requires 'project_id' field",
		},
		{
			name: "empty secret_id field",
			config: map[string]interface{}{
				"project_id": "my-project",
				"secret_id":  "",
			},
			wantErr: true,
			errMsg:  "gcloud_secretmanager provider requires 'secret_id' field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			secretContext := secrets.NewEmptySecretContext(ctx)
			_, err := provider.Fetch(secretContext, "test-map", tt.config, nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("GCSMProvider.Fetch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil {
				if tt.errMsg != "" && err.Error() != "" {
					// Check if error message contains expected substring
					if !containsSubstring(err.Error(), tt.errMsg) {
						t.Errorf("GCSMProvider.Fetch() error = %v, want error containing %v", err.Error(), tt.errMsg)
					}
				}
			}
		})
	}
}

func TestGCSMProvider_Name(t *testing.T) {
	provider := &GCSMProvider{}
	if got := provider.Name(); got != "gcloud_secretmanager" {
		t.Errorf("GCSMProvider.Name() = %v, want %v", got, "gcloud_secretmanager")
	}
}

func TestGCSMProvider_ConfigFields(t *testing.T) {
	// Test that all config fields are properly parsed and accessible
	config := map[string]interface{}{
		"project_id": "my-project",
		"secret_id":  "my-secret",
		"version":    "1",
		"endpoint":   "http://localhost:8080",
	}

	cfg, err := parseConfig(config)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	if cfg.ProjectID != "my-project" {
		t.Errorf("Config.ProjectID = %v, want %v", cfg.ProjectID, "my-project")
	}
	if cfg.SecretID != "my-secret" {
		t.Errorf("Config.SecretID = %v, want %v", cfg.SecretID, "my-secret")
	}
	if cfg.Version != "1" {
		t.Errorf("Config.Version = %v, want %v", cfg.Version, "1")
	}
	if cfg.Endpoint != "http://localhost:8080" {
		t.Errorf("Config.Endpoint = %v, want %v", cfg.Endpoint, "http://localhost:8080")
	}
}

func TestGCSMProvider_ConfigWithOptionalFields(t *testing.T) {
	// Test that optional fields can be omitted
	config := map[string]interface{}{
		"project_id": "my-project",
		"secret_id":  "my-secret",
	}

	cfg, err := parseConfig(config)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	if cfg.ProjectID != "my-project" {
		t.Errorf("Config.ProjectID = %v, want %v", cfg.ProjectID, "my-project")
	}
	if cfg.SecretID != "my-secret" {
		t.Errorf("Config.SecretID = %v, want %v", cfg.SecretID, "my-secret")
	}
	if cfg.Version != "" {
		t.Errorf("Config.Version = %v, want empty string", cfg.Version)
	}
	if cfg.Endpoint != "" {
		t.Errorf("Config.Endpoint = %v, want empty string", cfg.Endpoint)
	}
}

func TestGCSMProvider_ConfigWithExtraFields(t *testing.T) {
	// Test that extra unknown fields don't break parsing
	config := map[string]interface{}{
		"project_id": "my-project",
		"secret_id":  "my-secret",
		"unknown":    "field",
		"extra":      123,
	}

	cfg, err := parseConfig(config)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	// Should still parse known fields correctly
	if cfg.ProjectID != "my-project" {
		t.Errorf("Config.ProjectID = %v, want %v", cfg.ProjectID, "my-project")
	}
	if cfg.SecretID != "my-secret" {
		t.Errorf("Config.SecretID = %v, want %v", cfg.SecretID, "my-secret")
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


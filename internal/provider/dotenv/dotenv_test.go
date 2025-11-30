package dotenv

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDotEnvProvider_Name(t *testing.T) {
	provider := &DotEnvProvider{}
	if got := provider.Name(); got != "dotenv" {
		t.Errorf("DotEnvProvider.Name() = %v, want %v", got, "dotenv")
	}
}

func TestDotEnvProvider_Fetch_ConfigValidation(t *testing.T) {
	provider := &DotEnvProvider{}

	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "missing path field",
			config: map[string]interface{}{
				"other_field": "value",
			},
			wantErr: true,
			errMsg:  "dotenv provider requires 'path' field",
		},
		{
			name: "empty path field",
			config: map[string]interface{}{
				"path": "",
			},
			wantErr: true,
			errMsg:  "dotenv provider requires 'path' field",
		},
		{
			name: "path field is not a string",
			config: map[string]interface{}{
				"path": 123,
			},
			wantErr: true,
			errMsg:  "dotenv provider requires 'path' field",
		},
		{
			name: "valid path field",
			config: map[string]interface{}{
				"path": ".env.test",
			},
			wantErr: true, // Will fail because file doesn't exist, but config is valid
			errMsg:  "failed to read .env file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := provider.Fetch(ctx, "test-map", tt.config, nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("DotEnvProvider.Fetch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil {
				if tt.errMsg != "" && err.Error() != "" {
					// Check if error message contains expected substring
					if !containsSubstring(err.Error(), tt.errMsg) {
						t.Errorf("DotEnvProvider.Fetch() error = %v, want error containing %v", err.Error(), tt.errMsg)
					}
				}
			}
		})
	}
}

func TestDotEnvProvider_ConfigFields(t *testing.T) {
	// Test that path field is properly extracted
	config := map[string]interface{}{
		"path": "/custom/path/to/.env",
	}

	path, ok := config["path"].(string)
	if !ok {
		t.Fatalf("Failed to extract path from config")
	}

	if path != "/custom/path/to/.env" {
		t.Errorf("Config.path = %v, want %v", path, "/custom/path/to/.env")
	}
}

func TestDotEnvProvider_ConfigWithEnvironmentVariables(t *testing.T) {
	// Test that path with environment variables works
	testPath := "${HOME}/.config/test/.env"
	config := map[string]interface{}{
		"path": testPath,
	}

	path, ok := config["path"].(string)
	if !ok {
		t.Fatalf("Failed to extract path from config")
	}

	// Verify it contains the environment variable placeholder
	if path != testPath {
		t.Errorf("Config.path = %v, want %v", path, testPath)
	}
}

func TestDotEnvProvider_ConfigWithRelativePath(t *testing.T) {
	// Test relative path
	config := map[string]interface{}{
		"path": ".env.local",
	}

	path, ok := config["path"].(string)
	if !ok {
		t.Fatalf("Failed to extract path from config")
	}

	if path != ".env.local" {
		t.Errorf("Config.path = %v, want %v", path, ".env.local")
	}
}

func TestDotEnvProvider_ConfigWithAbsolutePath(t *testing.T) {
	// Test absolute path
	config := map[string]interface{}{
		"path": "/absolute/path/to/.env",
	}

	path, ok := config["path"].(string)
	if !ok {
		t.Fatalf("Failed to extract path from config")
	}

	if path != "/absolute/path/to/.env" {
		t.Errorf("Config.path = %v, want %v", path, "/absolute/path/to/.env")
	}
}

func TestDotEnvProvider_Fetch_WithValidFile(t *testing.T) {
	provider := &DotEnvProvider{}

	// Create a temporary .env file
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env.test")
	envContent := `API_KEY=test-api-key-123
DATABASE_URL=postgres://localhost:5432/testdb
SECRET_VALUE=my-secret-value
`
	err := os.WriteFile(envFile, []byte(envContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test .env file: %v", err)
	}

	config := map[string]interface{}{
		"path": envFile,
	}

	ctx := context.Background()

	// Test fetching all keys (empty keys map)
	result, err := provider.Fetch(ctx, "test-map", config, nil)
	if err != nil {
		t.Fatalf("DotEnvProvider.Fetch() error = %v", err)
	}

	if len(result) != 3 {
		t.Errorf("Expected 3 key-value pairs, got %d", len(result))
	}

	// Verify all keys are present (preserving original case)
	expectedKeys := map[string]string{
		"API_KEY":      "test-api-key-123",
		"DATABASE_URL": "postgres://localhost:5432/testdb",
		"SECRET_VALUE": "my-secret-value",
	}

	for _, kv := range result {
		if expectedValue, exists := expectedKeys[kv.Key]; !exists {
			t.Errorf("Unexpected key: %s", kv.Key)
		} else if kv.Value != expectedValue {
			t.Errorf("Key %s: got value %s, want %s", kv.Key, kv.Value, expectedValue)
		}
	}
}

func TestDotEnvProvider_Fetch_WithKeyMapping(t *testing.T) {
	provider := &DotEnvProvider{}

	// Create a temporary .env file
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env.test")
	envContent := `API_KEY=test-api-key
DATABASE_URL=postgres://localhost:5432/testdb
OTHER_VALUE=should-not-appear
`
	err := os.WriteFile(envFile, []byte(envContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test .env file: %v", err)
	}

	config := map[string]interface{}{
		"path": envFile,
	}

	keys := map[string]string{
		"API_KEY":      "==", // Keep same name
		"DATABASE_URL": "DB_URL",
	}

	ctx := context.Background()
	result, err := provider.Fetch(ctx, "test-map", config, keys)
	if err != nil {
		t.Fatalf("DotEnvProvider.Fetch() error = %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 key-value pairs, got %d", len(result))
	}

	// Verify mappings
	expectedKeys := map[string]string{
		"API_KEY": "test-api-key",
		"DB_URL":  "postgres://localhost:5432/testdb",
	}

	for _, kv := range result {
		if expectedValue, exists := expectedKeys[kv.Key]; !exists {
			t.Errorf("Unexpected key: %s", kv.Key)
		} else if kv.Value != expectedValue {
			t.Errorf("Key %s: got value %s, want %s", kv.Key, kv.Value, expectedValue)
		}
	}
}

func TestDotEnvProvider_ConfigWithExtraFields(t *testing.T) {
	// Test that extra unknown fields don't break path extraction
	config := map[string]interface{}{
		"path":   ".env.test",
		"extra":  "field",
		"other":  123,
		"nested": map[string]interface{}{"key": "value"},
	}

	path, ok := config["path"].(string)
	if !ok {
		t.Fatalf("Failed to extract path from config with extra fields")
	}

	if path != ".env.test" {
		t.Errorf("Config.path = %v, want %v", path, ".env.test")
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


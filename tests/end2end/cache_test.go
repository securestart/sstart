package end2end

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dirathea/sstart/internal/cache"
	"github.com/dirathea/sstart/internal/config"
	_ "github.com/dirathea/sstart/internal/provider/dotenv"
	"github.com/dirathea/sstart/internal/secrets"
)

// TestE2E_Cache_BasicCaching tests that secrets are cached and reused
func TestE2E_Cache_BasicCaching(t *testing.T) {
	// Skip if keyring not available
	testCache := cache.New()
	if !testCache.IsAvailable() {
		t.Skip("keyring not available, skipping cache test")
	}

	// Clean up any existing cache
	_ = testCache.Clear()

	// Create temp directory for test files
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	// Create initial .env file
	initialEnv := "API_KEY=initial-secret\nDB_PASS=initial-password\n"
	if err := os.WriteFile(envFile, []byte(initialEnv), 0600); err != nil {
		t.Fatalf("Failed to write env file: %v", err)
	}

	// Create config with caching enabled
	configContent := `
cache:
  enabled: true
  ttl: 1m

providers:
  - kind: dotenv
    id: test-env
    path: ` + envFile + `
`
	if err := os.WriteFile(configFile, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load config
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify cache is enabled
	if !cfg.IsCacheEnabled() {
		t.Fatal("Expected cache to be enabled")
	}

	// Create collector
	collector := secrets.NewCollector(cfg)

	// First collection - should fetch from provider
	ctx := context.Background()
	secretsResult, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify initial secrets
	if secretsResult["API_KEY"] != "initial-secret" {
		t.Errorf("Expected API_KEY=initial-secret, got %s", secretsResult["API_KEY"])
	}
	if secretsResult["DB_PASS"] != "initial-password" {
		t.Errorf("Expected DB_PASS=initial-password, got %s", secretsResult["DB_PASS"])
	}

	// Modify .env file
	modifiedEnv := "API_KEY=modified-secret\nDB_PASS=modified-password\n"
	if err := os.WriteFile(envFile, []byte(modifiedEnv), 0600); err != nil {
		t.Fatalf("Failed to write modified env file: %v", err)
	}

	// Second collection - should use cached values (not the modified file)
	secretsResult2, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets second time: %v", err)
	}

	// Should still have initial values from cache
	if secretsResult2["API_KEY"] != "initial-secret" {
		t.Errorf("Expected cached API_KEY=initial-secret, got %s (cache not working)", secretsResult2["API_KEY"])
	}
	if secretsResult2["DB_PASS"] != "initial-password" {
		t.Errorf("Expected cached DB_PASS=initial-password, got %s (cache not working)", secretsResult2["DB_PASS"])
	}

	// Clean up
	_ = testCache.Clear()
}

// TestE2E_Cache_Disabled tests that caching can be disabled
func TestE2E_Cache_Disabled(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	// Create initial .env file
	initialEnv := "SECRET=value1\n"
	if err := os.WriteFile(envFile, []byte(initialEnv), 0600); err != nil {
		t.Fatalf("Failed to write env file: %v", err)
	}

	// Create config with caching disabled
	configContent := `
cache:
  enabled: false

providers:
  - kind: dotenv
    id: test-env
    path: ` + envFile + `
`
	if err := os.WriteFile(configFile, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.IsCacheEnabled() {
		t.Fatal("Expected cache to be disabled")
	}

	collector := secrets.NewCollector(cfg)
	ctx := context.Background()

	// First collection
	secrets1, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect: %v", err)
	}
	if secrets1["SECRET"] != "value1" {
		t.Errorf("Expected SECRET=value1, got %s", secrets1["SECRET"])
	}

	// Modify file
	if err := os.WriteFile(envFile, []byte("SECRET=value2\n"), 0600); err != nil {
		t.Fatalf("Failed to write env file: %v", err)
	}

	// Second collection - should get fresh value since cache is disabled
	secrets2, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect: %v", err)
	}
	if secrets2["SECRET"] != "value2" {
		t.Errorf("Expected fresh SECRET=value2, got %s", secrets2["SECRET"])
	}
}

// TestE2E_Cache_TTLExpiration tests that cache expires after TTL
func TestE2E_Cache_TTLExpiration(t *testing.T) {
	// Skip if keyring not available
	testCache := cache.New()
	if !testCache.IsAvailable() {
		t.Skip("keyring not available, skipping cache test")
	}

	// Clean up any existing cache
	_ = testCache.Clear()

	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	// Create .env file
	if err := os.WriteFile(envFile, []byte("DATA=first\n"), 0600); err != nil {
		t.Fatalf("Failed to write env file: %v", err)
	}

	// Create config with very short TTL
	configContent := `
cache:
  enabled: true
  ttl: 100ms

providers:
  - kind: dotenv
    id: test-env
    path: ` + envFile + `
`
	if err := os.WriteFile(configFile, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	collector := secrets.NewCollector(cfg)
	ctx := context.Background()

	// First collection
	secrets1, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect: %v", err)
	}
	if secrets1["DATA"] != "first" {
		t.Errorf("Expected DATA=first, got %s", secrets1["DATA"])
	}

	// Modify file
	if err := os.WriteFile(envFile, []byte("DATA=second\n"), 0600); err != nil {
		t.Fatalf("Failed to write env file: %v", err)
	}

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Second collection - should get fresh value since cache expired
	secrets2, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect: %v", err)
	}
	if secrets2["DATA"] != "second" {
		t.Errorf("Expected fresh DATA=second after TTL expiry, got %s", secrets2["DATA"])
	}

	// Clean up
	_ = testCache.Clear()
}

// TestE2E_Cache_ConfigParsing tests cache configuration parsing
func TestE2E_Cache_ConfigParsing(t *testing.T) {
	tests := []struct {
		name          string
		configContent string
		expectEnabled bool
		expectTTL     time.Duration
		expectError   bool
	}{
		{
			name: "cache enabled with TTL",
			configContent: `
cache:
  enabled: true
  ttl: 10m
providers:
  - kind: dotenv
    path: /tmp/test.env
`,
			expectEnabled: true,
			expectTTL:     10 * time.Minute,
		},
		{
			name: "cache disabled",
			configContent: `
cache:
  enabled: false
providers:
  - kind: dotenv
    path: /tmp/test.env
`,
			expectEnabled: false,
			expectTTL:     0,
		},
		{
			name: "no cache config",
			configContent: `
providers:
  - kind: dotenv
    path: /tmp/test.env
`,
			expectEnabled: false,
			expectTTL:     0,
		},
		{
			name: "cache with various TTL formats",
			configContent: `
cache:
  enabled: true
  ttl: 1h30m
providers:
  - kind: dotenv
    path: /tmp/test.env
`,
			expectEnabled: true,
			expectTTL:     90 * time.Minute,
		},
		{
			name: "invalid TTL format",
			configContent: `
cache:
  enabled: true
  ttl: invalid
providers:
  - kind: dotenv
    path: /tmp/test.env
`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, ".sstart.yml")

			if err := os.WriteFile(configFile, []byte(tt.configContent), 0600); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			cfg, err := config.Load(configFile)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if cfg.IsCacheEnabled() != tt.expectEnabled {
				t.Errorf("Expected cache enabled=%v, got %v", tt.expectEnabled, cfg.IsCacheEnabled())
			}

			if cfg.GetCacheTTL() != tt.expectTTL {
				t.Errorf("Expected TTL=%v, got %v", tt.expectTTL, cfg.GetCacheTTL())
			}
		})
	}
}

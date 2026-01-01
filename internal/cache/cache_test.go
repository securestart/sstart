package cache

import (
	"fmt"
	"testing"
	"time"
)

func TestGenerateCacheKey(t *testing.T) {
	tests := []struct {
		name       string
		providerID string
		kind       string
		config     map[string]interface{}
	}{
		{
			name:       "simple config",
			providerID: "aws-prod",
			kind:       "aws_secretsmanager",
			config: map[string]interface{}{
				"region": "us-east-1",
				"secret": "my-secret",
			},
		},
		{
			name:       "empty config",
			providerID: "dotenv",
			kind:       "dotenv",
			config:     map[string]interface{}{},
		},
		{
			name:       "config with SSO tokens should be ignored",
			providerID: "vault",
			kind:       "vault",
			config: map[string]interface{}{
				"address":           "https://vault.example.com",
				"_sso_access_token": "token123",
				"_sso_id_token":     "idtoken456",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := GenerateCacheKey(tt.providerID, tt.kind, tt.config)
			if key == "" {
				t.Error("expected non-empty cache key")
			}
			// Key should be deterministic
			key2 := GenerateCacheKey(tt.providerID, tt.kind, tt.config)
			if key != key2 {
				t.Errorf("cache key should be deterministic, got %s and %s", key, key2)
			}
		})
	}
}

func TestGenerateCacheKey_DifferentConfigs(t *testing.T) {
	config1 := map[string]interface{}{"region": "us-east-1"}
	config2 := map[string]interface{}{"region": "us-west-2"}

	key1 := GenerateCacheKey("aws", "aws_secretsmanager", config1)
	key2 := GenerateCacheKey("aws", "aws_secretsmanager", config2)

	if key1 == key2 {
		t.Error("different configs should produce different cache keys")
	}
}

func TestGenerateCacheKey_SSOTokensIgnored(t *testing.T) {
	configWithoutToken := map[string]interface{}{
		"address": "https://vault.example.com",
	}
	configWithToken := map[string]interface{}{
		"address":           "https://vault.example.com",
		"_sso_access_token": "token123",
		"_sso_id_token":     "idtoken456",
	}

	key1 := GenerateCacheKey("vault", "vault", configWithoutToken)
	key2 := GenerateCacheKey("vault", "vault", configWithToken)

	if key1 != key2 {
		t.Error("SSO tokens should be ignored when generating cache key")
	}
}

func TestCache_SetAndGet(t *testing.T) {
	cache := New(WithTTL(time.Minute))

	// Skip if keyring not available
	if !cache.IsAvailable() {
		t.Skip("keyring not available")
	}

	// Clean up before test
	_ = cache.Clear()

	secrets := map[string]string{
		"API_KEY":     "secret123",
		"DB_PASSWORD": "dbpass456",
	}

	cacheKey := "test-key-123"

	// Set secrets
	err := cache.Set(cacheKey, secrets)
	if err != nil {
		t.Fatalf("failed to set cache: %v", err)
	}

	// Get secrets
	cached, found := cache.Get(cacheKey)
	if !found {
		t.Fatal("expected to find cached secrets")
	}

	if len(cached) != len(secrets) {
		t.Errorf("expected %d secrets, got %d", len(secrets), len(cached))
	}

	for k, v := range secrets {
		if cached[k] != v {
			t.Errorf("expected %s=%s, got %s=%s", k, v, k, cached[k])
		}
	}

	// Clean up
	_ = cache.Clear()
}

func TestCache_Expiration(t *testing.T) {
	// Use a very short TTL
	c := New(WithTTL(100 * time.Millisecond))

	// Skip if keyring not available
	if !c.IsAvailable() {
		t.Skip("keyring not available")
	}

	// Use unique key to avoid conflicts with other tests
	cacheKey := fmt.Sprintf("expiring-key-%d", time.Now().UnixNano())

	secrets := map[string]string{"KEY": "value"}

	err := c.Set(cacheKey, secrets)
	if err != nil {
		t.Fatalf("failed to set cache: %v", err)
	}

	// Should be found immediately
	_, found := c.Get(cacheKey)
	if !found {
		t.Fatal("expected to find cached secrets immediately after setting")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should be expired now
	_, found = c.Get(cacheKey)
	if found {
		t.Error("expected cache to be expired")
	}
}

func TestCache_Clear(t *testing.T) {
	cache := New()

	// Skip if keyring not available
	if !cache.IsAvailable() {
		t.Skip("keyring not available")
	}

	secrets := map[string]string{"KEY": "value"}
	cacheKey := "clear-test-key"

	_ = cache.Set(cacheKey, secrets)

	// Verify it's set
	_, found := cache.Get(cacheKey)
	if !found {
		t.Fatal("expected to find cached secrets before clear")
	}

	// Clear cache
	err := cache.Clear()
	if err != nil {
		t.Fatalf("failed to clear cache: %v", err)
	}

	// Should not be found after clear
	_, found = cache.Get(cacheKey)
	if found {
		t.Error("expected cache to be cleared")
	}
}

func TestCache_ClearProvider(t *testing.T) {
	cache := New()

	// Skip if keyring not available
	if !cache.IsAvailable() {
		t.Skip("keyring not available")
	}

	// Clean up before test
	_ = cache.Clear()

	secrets1 := map[string]string{"KEY1": "value1"}
	secrets2 := map[string]string{"KEY2": "value2"}

	_ = cache.Set("provider1", secrets1)
	_ = cache.Set("provider2", secrets2)

	// Clear only provider1
	err := cache.ClearProvider("provider1")
	if err != nil {
		t.Fatalf("failed to clear provider: %v", err)
	}

	// provider1 should be gone
	_, found := cache.Get("provider1")
	if found {
		t.Error("expected provider1 to be cleared")
	}

	// provider2 should still exist
	_, found = cache.Get("provider2")
	if !found {
		t.Error("expected provider2 to still exist")
	}

	// Clean up
	_ = cache.Clear()
}

func TestCache_CleanExpired(t *testing.T) {
	c := New(WithTTL(50 * time.Millisecond))

	// Skip if keyring not available
	if !c.IsAvailable() {
		t.Skip("keyring not available")
	}

	// Clean up before test
	_ = c.Clear()

	secrets := map[string]string{"KEY": "value"}
	_ = c.Set("expiring", secrets)

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Add a fresh entry with longer TTL
	c2 := New(WithTTL(time.Hour))
	_ = c2.Set("fresh", map[string]string{"KEY2": "value2"})

	// Clean expired
	err := c2.CleanExpired()
	if err != nil {
		t.Fatalf("failed to clean expired: %v", err)
	}

	// Expired should be gone
	_, found := c2.Get("expiring")
	if found {
		t.Error("expected expired entry to be cleaned")
	}

	// Fresh should still exist
	_, found = c2.Get("fresh")
	if !found {
		t.Error("expected fresh entry to still exist")
	}

	// Clean up
	_ = c2.Clear()
}

func TestCache_Stats(t *testing.T) {
	// Skip if keyring not available
	c := New()
	if !c.IsAvailable() {
		t.Skip("keyring not available")
	}

	// Clean up before test to get fresh state
	_ = c.Clear()

	// Initially empty
	total, valid, expired := c.Stats()
	if total != 0 {
		t.Errorf("expected empty stats after clear, got total=%d", total)
	}

	// Use short-lived cache for this test
	shortCache := New(WithTTL(150 * time.Millisecond))

	// Use unique keys
	key1 := fmt.Sprintf("stats-key1-%d", time.Now().UnixNano())
	key2 := fmt.Sprintf("stats-key2-%d", time.Now().UnixNano())

	// Add entries quickly
	_ = shortCache.Set(key1, map[string]string{"K": "V"})
	_ = shortCache.Set(key2, map[string]string{"K": "V"})

	total, valid, expired = shortCache.Stats()
	if valid != 2 {
		t.Errorf("expected 2 valid entries immediately after set, got valid=%d, expired=%d", valid, expired)
	}

	// Wait for expiration
	time.Sleep(200 * time.Millisecond)

	total, valid, expired = shortCache.Stats()
	if expired != 2 {
		t.Errorf("expected 2 expired entries after TTL, got valid=%d, expired=%d", valid, expired)
	}

	// Clean up
	_ = c.Clear()
}

func TestCache_GetTTL(t *testing.T) {
	cache := New(WithTTL(10 * time.Minute))
	if cache.GetTTL() != 10*time.Minute {
		t.Errorf("expected TTL of 10m, got %v", cache.GetTTL())
	}

	cache2 := New() // Default TTL
	if cache2.GetTTL() != DefaultTTL {
		t.Errorf("expected default TTL of %v, got %v", DefaultTTL, cache2.GetTTL())
	}
}

func TestCache_IsAvailable(t *testing.T) {
	cache := New()
	// Just verify the method doesn't panic
	_ = cache.IsAvailable()
}

func TestCache_KeyringNotAvailable(t *testing.T) {
	cache := New()
	// Force keyring to be disabled
	cache.keyringTested = true
	cache.keyringDisabled = true

	// All operations should gracefully handle unavailable keyring
	// Get should return not found (forcing provider fetch)
	_, found := cache.Get("any-key")
	if found {
		t.Error("expected not found when keyring unavailable")
	}

	// Set should silently succeed (no-op)
	err := cache.Set("any-key", map[string]string{"K": "V"})
	if err != nil {
		t.Errorf("expected no error when setting with keyring unavailable, got %v", err)
	}

	// Get should still return not found (nothing was actually cached)
	_, found = cache.Get("any-key")
	if found {
		t.Error("expected not found after set when keyring unavailable")
	}

	// Clear should not error
	err = cache.Clear()
	if err != nil {
		t.Errorf("expected no error on clear, got %v", err)
	}

	// Stats should return zeros
	total, valid, expired := cache.Stats()
	if total != 0 || valid != 0 || expired != 0 {
		t.Errorf("expected zero stats, got total=%d, valid=%d, expired=%d", total, valid, expired)
	}

	// IsAvailable should return false
	if cache.IsAvailable() {
		t.Error("expected IsAvailable to return false")
	}
}

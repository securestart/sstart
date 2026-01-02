// Package cache provides secret caching functionality using the system keyring.
// Secrets are cached with a configurable TTL to reduce API calls to providers.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

const (
	// KeyringService is the service name used for keyring storage
	KeyringService = "sstart-cache"
	// DefaultTTL is the default cache TTL (5 minutes)
	DefaultTTL = 5 * time.Minute
)

// CachedSecrets represents cached secrets with metadata
type CachedSecrets struct {
	Secrets   map[string]string `json:"secrets"`
	ExpiresAt time.Time         `json:"expires_at"`
	CachedAt  time.Time         `json:"cached_at"`
}

// CacheStore represents the entire cache storage
type CacheStore struct {
	Providers map[string]*CachedSecrets `json:"providers"`
}

// Cache provides caching functionality for secrets
type Cache struct {
	ttl             time.Duration
	keyringDisabled bool
	keyringOnce     sync.Once
}

// Option is a functional option for configuring the Cache
type Option func(*Cache)

// WithTTL sets a custom TTL for the cache
func WithTTL(ttl time.Duration) Option {
	return func(c *Cache) {
		c.ttl = ttl
	}
}

// New creates a new Cache instance
func New(opts ...Option) *Cache {
	cache := &Cache{
		ttl: DefaultTTL,
	}

	for _, opt := range opts {
		opt(cache)
	}

	return cache
}

// GenerateCacheKey generates a unique cache key based on provider configuration.
// The key is a hash of the provider kind, id, and configuration.
func GenerateCacheKey(providerID string, kind string, config map[string]interface{}) string {
	// Create a deterministic representation of the config
	data := map[string]interface{}{
		"provider_id": providerID,
		"kind":        kind,
		"config":      sortedConfigString(config),
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		// Fallback to simple key if marshaling fails
		return providerID
	}

	hash := sha256.Sum256(jsonBytes)
	return hex.EncodeToString(hash[:])
}

// sortedConfigString creates a deterministic string representation of config
func sortedConfigString(config map[string]interface{}) string {
	if config == nil {
		return "{}"
	}

	// Get sorted keys
	keys := make([]string, 0, len(config))
	for k := range config {
		// Skip internal SSO tokens as they change
		if k == "_sso_access_token" || k == "_sso_id_token" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build sorted representation
	result := make(map[string]interface{})
	for _, k := range keys {
		result[k] = config[k]
	}

	jsonBytes, _ := json.Marshal(result)
	return string(jsonBytes)
}

// Get retrieves cached secrets for a provider if they exist and are not expired
func (c *Cache) Get(cacheKey string) (map[string]string, bool) {
	if !c.isKeyringAvailable() {
		return nil, false
	}

	store := c.loadStore()
	if store == nil {
		return nil, false
	}

	cached, exists := store.Providers[cacheKey]
	if !exists || cached == nil {
		return nil, false
	}

	// Check if expired
	if time.Now().After(cached.ExpiresAt) {
		// Clean up expired entry
		delete(store.Providers, cacheKey)
		_ = c.saveStore(store)
		return nil, false
	}

	return cached.Secrets, true
}

// Set stores secrets in the cache with the configured TTL.
// If keyring is not available, this is a no-op (returns nil).
func (c *Cache) Set(cacheKey string, secrets map[string]string) error {
	if !c.isKeyringAvailable() {
		// Silently skip caching when keyring is not available
		return nil
	}

	store := c.loadStore()
	if store == nil {
		store = &CacheStore{
			Providers: make(map[string]*CachedSecrets),
		}
	}
	// Ensure Providers map is initialized (handles corrupted cache)
	if store.Providers == nil {
		store.Providers = make(map[string]*CachedSecrets)
	}

	now := time.Now()
	store.Providers[cacheKey] = &CachedSecrets{
		Secrets:   secrets,
		CachedAt:  now,
		ExpiresAt: now.Add(c.ttl),
	}

	return c.saveStore(store)
}

// Clear removes all cached secrets
func (c *Cache) Clear() error {
	if !c.isKeyringAvailable() {
		return nil
	}

	if err := keyring.Delete(KeyringService, "cache"); err != nil && err != keyring.ErrNotFound {
		return fmt.Errorf("failed to remove cache from keyring: %w", err)
	}

	return nil
}

// ClearProvider removes cached secrets for a specific provider
func (c *Cache) ClearProvider(cacheKey string) error {
	if !c.isKeyringAvailable() {
		return nil
	}

	store := c.loadStore()
	if store == nil {
		return nil
	}

	delete(store.Providers, cacheKey)
	return c.saveStore(store)
}

// CleanExpired removes all expired cache entries
func (c *Cache) CleanExpired() error {
	if !c.isKeyringAvailable() {
		return nil
	}

	store := c.loadStore()
	if store == nil {
		return nil
	}

	now := time.Now()
	changed := false
	for key, cached := range store.Providers {
		if cached == nil || now.After(cached.ExpiresAt) {
			delete(store.Providers, key)
			changed = true
		}
	}

	if changed {
		return c.saveStore(store)
	}
	return nil
}

// isKeyringAvailable checks if keyring is available on this system
func (c *Cache) isKeyringAvailable() bool {
	c.keyringOnce.Do(func() {
		// Try to access keyring with a test operation
		_, err := keyring.Get(KeyringService, "test-availability")
		if err != nil && err != keyring.ErrNotFound {
			c.keyringDisabled = true
		}
	})

	return !c.keyringDisabled
}

// loadStore loads the cache store from keyring
func (c *Cache) loadStore() *CacheStore {
	data, err := keyring.Get(KeyringService, "cache")
	if err != nil {
		return nil
	}

	var store CacheStore
	if err := json.Unmarshal([]byte(data), &store); err != nil {
		// Invalid data, clean up
		_ = keyring.Delete(KeyringService, "cache")
		return nil
	}

	return &store
}

// saveStore saves the cache store to keyring
func (c *Cache) saveStore(store *CacheStore) error {
	data, err := json.Marshal(store)
	if err != nil {
		return fmt.Errorf("failed to marshal cache store: %w", err)
	}

	if err := keyring.Set(KeyringService, "cache", string(data)); err != nil {
		return fmt.Errorf("failed to save cache to keyring: %w", err)
	}

	return nil
}

// GetTTL returns the configured TTL
func (c *Cache) GetTTL() time.Duration {
	return c.ttl
}

// Stats returns cache statistics
func (c *Cache) Stats() (total int, valid int, expired int) {
	if !c.isKeyringAvailable() {
		return 0, 0, 0
	}

	store := c.loadStore()
	if store == nil {
		return 0, 0, 0
	}

	now := time.Now()
	for _, cached := range store.Providers {
		if cached == nil {
			continue
		}
		total++
		if now.Before(cached.ExpiresAt) {
			valid++
		} else {
			expired++
		}
	}
	return total, valid, expired
}

// IsAvailable returns whether the cache backend (keyring) is available
func (c *Cache) IsAvailable() bool {
	return c.isKeyringAvailable()
}

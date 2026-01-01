package secrets

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/dirathea/sstart/internal/cache"
	"github.com/dirathea/sstart/internal/config"
	"github.com/dirathea/sstart/internal/oidc"
	"github.com/dirathea/sstart/internal/provider"
)

const (
	// AccessTokenConfigKey is the key used to inject access token into provider config
	AccessTokenConfigKey = "_sso_access_token"
	// IDTokenConfigKey is the key used to inject ID token into provider config
	IDTokenConfigKey = "_sso_id_token"
)

// Collector collects secrets from all configured providers
type Collector struct {
	config      *config.Config
	ssoClient   *oidc.Client
	accessToken string
	idToken     string
	forceAuth   bool
	cache       *cache.Cache
}

// CollectorOption is a functional option for configuring the Collector
type CollectorOption func(*Collector)

// WithForceAuth returns an option that forces re-authentication by ignoring cached tokens
func WithForceAuth(forceAuth bool) CollectorOption {
	return func(c *Collector) {
		c.forceAuth = forceAuth
	}
}

// NewCollector creates a new secrets collector
func NewCollector(cfg *config.Config, opts ...CollectorOption) *Collector {
	collector := &Collector{config: cfg}

	// Apply options
	for _, opt := range opts {
		opt(collector)
	}

	// Initialize SSO client if configured
	if cfg.SSO != nil && cfg.SSO.OIDC != nil {
		client, err := oidc.NewClient(cfg.SSO.OIDC)
		if err == nil {
			collector.ssoClient = client
		}
	}

	// Initialize cache if enabled
	if cfg.IsCacheEnabled() {
		cacheOpts := []cache.Option{}
		if ttl := cfg.GetCacheTTL(); ttl > 0 {
			cacheOpts = append(cacheOpts, cache.WithTTL(ttl))
		}
		collector.cache = cache.New(cacheOpts...)
	}

	return collector
}

// Collect fetches secrets from all providers and combines them
func (c *Collector) Collect(ctx context.Context, providerIDs []string) (provider.Secrets, error) {
	secrets := make(provider.Secrets)
	// Track secrets by provider ID for template providers
	providerSecrets := make(provider.ProviderSecretsMap)

	// Authenticate with SSO if configured
	if err := c.authenticateSSO(ctx); err != nil {
		return nil, fmt.Errorf("SSO authentication failed: %w", err)
	}

	// If no providers specified, use all providers in order
	if len(providerIDs) == 0 {
		for _, provider := range c.config.Providers {
			providerIDs = append(providerIDs, provider.ID)
		}
	}

	// Collect from each provider
	for _, providerID := range providerIDs {
		providerCfg, err := c.config.GetProvider(providerID)
		if err != nil {
			return nil, err
		}

		// Expand template variables in config (e.g., in path fields)
		expandedConfig := expandConfigTemplates(providerCfg.Config)

		// Generate cache key based on provider configuration
		cacheKey := cache.GenerateCacheKey(providerID, providerCfg.Kind, expandedConfig)

		// Try to get secrets from cache if enabled
		if c.cache != nil {
			if cachedSecrets, found := c.cache.Get(cacheKey); found {
				// Use cached secrets
				providerSecrets[providerID] = cachedSecrets
				for k, v := range cachedSecrets {
					secrets[k] = v
				}
				continue
			}
		}

		// Create provider instance
		prov, err := provider.New(providerCfg.Kind)
		if err != nil {
			return nil, fmt.Errorf("failed to create provider '%s': %w", providerID, err)
		}

		// Inject SSO tokens into provider config if available
		c.injectTokensIntoConfig(expandedConfig)

		// Create SecretContext with resolver for providers
		// Providers can optionally use SecretsResolver to access secrets from other providers
		// This follows the principle of least privilege - providers only access secrets they explicitly request
		// If 'uses' is specified, create a filtered resolver that only includes secrets from allowed providers
		// If 'uses' is not specified, pass an empty resolver (no access to other providers' secrets)
		var secretContext provider.SecretContext
		if len(providerCfg.Uses) > 0 {
			secretContext = NewSecretContext(ctx, providerSecrets, providerCfg.Uses)
		} else {
			// Pass empty provider secrets map when 'uses' is not defined
			secretContext = NewEmptySecretContext(ctx)
		}

		// Fetch secrets from this provider's single source
		kvs, err := prov.Fetch(secretContext, providerCfg.ID, expandedConfig, providerCfg.Keys)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch from provider '%s': %w", providerID, err)
		}

		// Store secrets by provider ID for resolver
		providerSecrets[providerID] = make(provider.Secrets)
		for _, kv := range kvs {
			providerSecrets[providerID][kv.Key] = kv.Value
		}

		// Cache the secrets if caching is enabled
		if c.cache != nil {
			_ = c.cache.Set(cacheKey, providerSecrets[providerID])
		}

		// Merge secrets (later providers override earlier ones)
		for _, kv := range kvs {
			secrets[kv.Key] = kv.Value
		}
	}

	return secrets, nil
}

// authenticateSSO handles SSO authentication if configured
func (c *Collector) authenticateSSO(ctx context.Context) error {
	if c.ssoClient == nil {
		return nil
	}

	// Check if already authenticated (skip if --force-auth is set)
	if !c.forceAuth && c.ssoClient.IsAuthenticated() {
		// Try to get the access token
		token, err := c.ssoClient.GetAccessToken(ctx)
		if err == nil {
			c.accessToken = token
			// Also get ID token if available
			tokens, err := c.ssoClient.GetTokens()
			if err == nil && tokens.IDToken != "" {
				c.idToken = tokens.IDToken
			}
			return nil
		}
		// Token expired or invalid, need to re-authenticate
	}

	// If client credentials are configured, use client credentials flow (non-interactive)
	// This is for CI/CD and service accounts - never fall back to browser
	if c.ssoClient.HasClientCredentials() {
		result, err := c.ssoClient.LoginWithClientCredentials(ctx)
		if err != nil {
			return fmt.Errorf("client credentials authentication failed: %w", err)
		}
		// Store tokens
		if result.Tokens != nil {
			c.accessToken = result.Tokens.AccessToken
			c.idToken = result.Tokens.IDToken
		}
		return nil
	}

	// No client secret configured - use interactive login flow (browser-based)
	result, err := c.ssoClient.Login(ctx)
	if err != nil {
		return err
	}

	// Store tokens
	if result.Tokens != nil {
		c.accessToken = result.Tokens.AccessToken
		c.idToken = result.Tokens.IDToken
	}

	return nil
}

// injectTokensIntoConfig adds SSO tokens to the provider config for provider authentication
func (c *Collector) injectTokensIntoConfig(config map[string]interface{}) {
	if c.accessToken != "" {
		config[AccessTokenConfigKey] = c.accessToken
	}
	if c.idToken != "" {
		config[IDTokenConfigKey] = c.idToken
	}
}

// expandConfigTemplates expands template variables in config values
// Supports {{ get_env(name="VAR", default="default") }} syntax
func expandConfigTemplates(config map[string]interface{}) map[string]interface{} {
	expanded := make(map[string]interface{})
	for k, v := range config {
		switch val := v.(type) {
		case string:
			expanded[k] = expandTemplate(val)
		case map[string]interface{}:
			expanded[k] = expandConfigTemplates(val)
		case []interface{}:
			expandedSlice := make([]interface{}, len(val))
			for i, item := range val {
				if str, ok := item.(string); ok {
					expandedSlice[i] = expandTemplate(str)
				} else {
					expandedSlice[i] = item
				}
			}
			expanded[k] = expandedSlice
		default:
			expanded[k] = v
		}
	}
	return expanded
}

// expandTemplate expands template variables in a string
// Supports {{ get_env(name="VAR", default="default") }} syntax
func expandTemplate(template string) string {
	// Simple implementation: expand environment variables
	re := regexp.MustCompile(`\{\{\s*get_env\(name="([^"]+)",\s*default="([^"]+)"\)\s*\}\}`)
	result := re.ReplaceAllStringFunc(template, func(match string) string {
		matches := re.FindStringSubmatch(match)
		if len(matches) == 3 {
			envVar := matches[1]
			defaultValue := matches[2]
			if value := os.Getenv(envVar); value != "" {
				return value
			}
			return defaultValue
		}
		return match
	})

	// Also support simple ${VAR} or $VAR syntax
	result = os.ExpandEnv(result)

	return result
}

// Redact redacts secrets from text
func Redact(text string, secrets provider.Secrets) string {
	result := text
	for _, value := range secrets {
		if len(value) > 0 {
			// Redact the full value
			mask := strings.Repeat("*", len(value))
			result = strings.ReplaceAll(result, value, mask)
		}
	}
	return result
}

// Mask masks a secret value, showing only first and last characters
func Mask(value string) string {
	if len(value) <= 4 {
		return "****"
	}
	if len(value) <= 8 {
		return value[:2] + "****"
	}
	return value[:2] + "****" + value[len(value)-2:]
}

// ClearCache clears all cached secrets
func (c *Collector) ClearCache() error {
	if c.cache == nil {
		return nil
	}
	return c.cache.Clear()
}

// GetCache returns the cache instance (for testing or advanced usage)
func (c *Collector) GetCache() *cache.Cache {
	return c.cache
}

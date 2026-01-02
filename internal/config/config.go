package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Inherit   bool             `yaml:"inherit"` // Whether to inherit system environment variables (default: true)
	Providers []ProviderConfig `yaml:"providers"`
	SSO       *SSOConfig       `yaml:"sso,omitempty"`   // SSO configuration
	Cache     *CacheConfig     `yaml:"cache,omitempty"` // Cache configuration
}

// CacheConfig represents cache configuration
type CacheConfig struct {
	Enabled bool          `yaml:"enabled"`       // Whether caching is enabled (default: false)
	TTL     time.Duration `yaml:"ttl,omitempty"` // Cache TTL (default: 5m)
}

// UnmarshalYAML implements custom YAML unmarshaling to handle TTL as duration string
func (c *CacheConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawCacheConfig struct {
		Enabled bool   `yaml:"enabled"`
		TTL     string `yaml:"ttl,omitempty"`
	}

	var raw rawCacheConfig
	if err := unmarshal(&raw); err != nil {
		return err
	}

	c.Enabled = raw.Enabled

	// Parse TTL if provided
	if raw.TTL != "" {
		ttl, err := time.ParseDuration(raw.TTL)
		if err != nil {
			return fmt.Errorf("invalid cache TTL format '%s': %w", raw.TTL, err)
		}
		if ttl <= 0 {
			return fmt.Errorf("cache TTL must be positive, got '%s'", raw.TTL)
		}
		c.TTL = ttl
	}

	return nil
}

// SSOConfig represents SSO configuration
type SSOConfig struct {
	OIDC *OIDCConfig `yaml:"oidc,omitempty"` // OIDC configuration
}

// OIDCConfig represents OIDC configuration
type OIDCConfig struct {
	ClientID     string   `yaml:"clientId"`               // OIDC client ID (required)
	ClientSecret string   `yaml:"-"`                      // OIDC client secret (only from env var SSTART_SSO_SECRET, never from YAML)
	Issuer       string   `yaml:"issuer"`                 // OIDC issuer URL (required)
	Scopes       []string `yaml:"scopes"`                 // OIDC scopes (required)
	RedirectURI  string   `yaml:"redirectUri,omitempty"`  // OIDC redirect URI (optional, can be auto-generated)
	PKCE         *bool    `yaml:"pkce,omitempty"`         // Enable PKCE flow (optional, auto-enabled if clientSecret is empty)
	ResponseMode string   `yaml:"responseMode,omitempty"` // OIDC response mode (optional)
}

// UnmarshalYAML implements custom YAML unmarshaling to handle scopes as either array or space-separated string
func (o *OIDCConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Create a temporary struct to unmarshal into
	// Note: clientSecret is intentionally NOT parsed from YAML - it must be provided via SSTART_SSO_SECRET env var
	type rawOIDCConfig struct {
		ClientID     string      `yaml:"clientId"`
		Issuer       string      `yaml:"issuer"`
		Scopes       interface{} `yaml:"scopes"` // Use interface{} to handle both string and []string
		RedirectURI  string      `yaml:"redirectUri,omitempty"`
		PKCE         *bool       `yaml:"pkce,omitempty"`
		ResponseMode string      `yaml:"responseMode,omitempty"`
	}

	var raw rawOIDCConfig
	if err := unmarshal(&raw); err != nil {
		return err
	}

	// Copy fields (clientSecret is NOT copied - must come from env var)
	o.ClientID = raw.ClientID
	o.Issuer = raw.Issuer
	o.RedirectURI = raw.RedirectURI
	o.PKCE = raw.PKCE
	o.ResponseMode = raw.ResponseMode

	// Handle scopes: can be string (space-separated) or []string
	if raw.Scopes != nil {
		switch v := raw.Scopes.(type) {
		case string:
			// Split space-separated string
			if v != "" {
				o.Scopes = strings.Fields(v)
			} else {
				o.Scopes = []string{}
			}
		case []interface{}:
			// Convert []interface{} to []string
			o.Scopes = make([]string, 0, len(v))
			for _, item := range v {
				if str, ok := item.(string); ok {
					o.Scopes = append(o.Scopes, str)
				}
			}
		case []string:
			// Already []string
			o.Scopes = v
		default:
			return fmt.Errorf("invalid scopes format: expected string or array of strings")
		}
	}

	return nil
}

// ProviderConfig represents a single provider configuration
// Each provider loads from a single source. To load multiple secrets from the same provider type,
// configure multiple provider instances with the same 'kind' but different 'id' values.
type ProviderConfig struct {
	Kind   string                 `yaml:"kind"`
	ID     string                 `yaml:"id,omitempty"`   // Optional: defaults to 'kind'. Required if multiple providers share the same kind
	Config map[string]interface{} `yaml:"-"`              // Provider-specific configuration (e.g., path, region, endpoint, etc.)
	Keys   map[string]string      `yaml:"keys,omitempty"` // Optional key mappings (source_key: target_key, or "==" to keep same name)
	Env    EnvVars                `yaml:"env,omitempty"`
	Uses   []string               `yaml:"uses,omitempty"` // Optional list of provider IDs to depend on
}

// UnmarshalYAML implements custom YAML unmarshaling to capture provider-specific fields
func (p *ProviderConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// First, unmarshal into a map to get all fields
	var raw map[string]interface{}
	if err := unmarshal(&raw); err != nil {
		return err
	}

	// Extract known fields
	if kind, ok := raw["kind"].(string); ok {
		p.Kind = kind
		delete(raw, "kind")
	}

	if id, ok := raw["id"].(string); ok {
		p.ID = id
		delete(raw, "id")
	}

	if keys, ok := raw["keys"].(map[string]interface{}); ok {
		p.Keys = make(map[string]string)
		for k, v := range keys {
			if str, ok := v.(string); ok {
				p.Keys[k] = str
			}
		}
		delete(raw, "keys")
	}

	if env, ok := raw["env"].(map[string]interface{}); ok {
		p.Env = make(EnvVars)
		for k, v := range env {
			if str, ok := v.(string); ok {
				p.Env[k] = str
			}
		}
		delete(raw, "env")
	}

	if uses, ok := raw["uses"].([]interface{}); ok {
		p.Uses = make([]string, 0, len(uses))
		for _, v := range uses {
			if str, ok := v.(string); ok {
				p.Uses = append(p.Uses, str)
			}
		}
		delete(raw, "uses")
	}

	// Everything else goes into Config
	p.Config = raw
	if p.Config == nil {
		p.Config = make(map[string]interface{})
	}

	return nil
}

// EnvVars represents environment variable overrides
type EnvVars map[string]string

// Load reads and parses the configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set default value for inherit (defaults to true)
	// Check if inherit was explicitly set in YAML, if not, default to true
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err == nil {
		if _, explicitlySet := raw["inherit"]; !explicitlySet {
			config.Inherit = true
		}
	} else {
		// If we can't parse the raw YAML, default to true
		config.Inherit = true
	}

	if config.Providers == nil {
		config.Providers = make([]ProviderConfig, 0)
	}

	// First pass: count kinds to identify duplicates
	kindCounts := make(map[string]int)
	for i := range config.Providers {
		provider := &config.Providers[i]

		// Validate required fields
		if provider.Kind == "" {
			return nil, fmt.Errorf("provider at index %d is missing required field 'kind'", i)
		}
		if provider.Config == nil {
			provider.Config = make(map[string]interface{})
		}

		kindCounts[provider.Kind]++
	}

	// Second pass: validate and set default IDs
	// If multiple providers have the same kind, they must have explicit, unique IDs
	for i := range config.Providers {
		provider := &config.Providers[i]

		// If this kind appears multiple times, ID is required
		if kindCounts[provider.Kind] > 1 {
			if provider.ID == "" {
				return nil, fmt.Errorf("provider at index %d with kind '%s' must have an explicit 'id' field because there are multiple providers of this kind", i, provider.Kind)
			}
		}

		// Use kind as default ID if not provided
		if provider.ID == "" {
			provider.ID = provider.Kind
		}
	}

	// Third pass: validate all IDs are unique
	idCounts := make(map[string]int)
	for i := range config.Providers {
		id := config.Providers[i].ID
		idCounts[id]++
		if idCounts[id] > 1 {
			return nil, fmt.Errorf("duplicate provider id '%s' found at index %d - all provider ids must be unique", id, i)
		}
	}

	// Validate SSO configuration if present
	if config.SSO != nil && config.SSO.OIDC != nil {
		oidc := config.SSO.OIDC
		if oidc.ClientID == "" {
			return nil, fmt.Errorf("sso.oidc.clientId is required")
		}
		if oidc.Issuer == "" {
			return nil, fmt.Errorf("sso.oidc.issuer is required")
		}
		if len(oidc.Scopes) == 0 {
			return nil, fmt.Errorf("sso.oidc.scopes is required and must contain at least one scope")
		}
	}

	return &config, nil
}

// GetProvider returns a provider configuration by id
func (c *Config) GetProvider(id string) (*ProviderConfig, error) {
	for i := range c.Providers {
		if c.Providers[i].ID == id {
			return &c.Providers[i], nil
		}
	}
	return nil, fmt.Errorf("provider '%s' not found", id)
}

// IsCacheEnabled returns whether caching is enabled globally
func (c *Config) IsCacheEnabled() bool {
	return c.Cache != nil && c.Cache.Enabled
}

// GetCacheTTL returns the cache TTL, or 0 if not configured
func (c *Config) GetCacheTTL() time.Duration {
	if c.Cache == nil {
		return 0
	}
	return c.Cache.TTL
}

package config

import (
	"fmt"
	"os"
	"text/template"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Inherit   bool             `yaml:"inherit"` // Whether to inherit system environment variables (default: true)
	Providers []ProviderConfig `yaml:"providers"`
}

// ProviderConfig represents a single provider configuration
// Each provider loads from a single source. To load multiple secrets from the same provider type,
// configure multiple provider instances with the same 'kind' but different 'id' values.
type ProviderConfig struct {
	Kind      string                 `yaml:"kind"`
	ID        string                 `yaml:"id,omitempty"`        // Optional: defaults to 'kind'. Required if multiple providers share the same kind
	Config    map[string]interface{} `yaml:"-"`                   // Provider-specific configuration (e.g., path, region, endpoint, etc.)
	Keys      map[string]string      `yaml:"keys,omitempty"`      // Optional key mappings (source_key: target_key, or "==" to keep same name)
	Templates []*template.Template   `yaml:"templates,omitempty"` // Optional templates mappings (target_key: str(Go template))
	Env       EnvVars                `yaml:"env,omitempty"`
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

	if templates, ok := raw["templates"].(map[string]interface{}); ok {
		for k, v := range templates {
			str, ok := v.(string)
			if !ok {
				return fmt.Errorf("invalid template format")
			}
			tmpl := template.New(k)
			if _, err := tmpl.Parse(str); err != nil {
				return err
			}
			p.Templates = append(p.Templates, tmpl)
		}
		delete(raw, "templates")
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

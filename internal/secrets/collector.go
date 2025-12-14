package secrets

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/template"

	"github.com/dirathea/sstart/internal/config"
	"github.com/dirathea/sstart/internal/provider"
)

// Collector collects secrets from all configured providers
type Collector struct {
	config *config.Config
}

// NewCollector creates a new secrets collector
func NewCollector(cfg *config.Config) *Collector {
	return &Collector{config: cfg}
}

// Collect fetches secrets from all providers and combines them
func (c *Collector) Collect(ctx context.Context, providerIDs []string) (map[string]string, error) {
	secrets := make(map[string]string)

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

		// Create provider instance
		prov, err := provider.New(providerCfg.Kind)
		if err != nil {
			return nil, fmt.Errorf("failed to create provider '%s': %w", providerID, err)
		}

		// Expand template variables in config (e.g., in path fields)
		expandedConfig := expandConfigTemplates(providerCfg.Config)

		// Fetch secrets from this provider's single source
		kvs, err := prov.Fetch(ctx, providerCfg.ID, expandedConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch from provider '%s': %w", providerID, err)
		}

		tmplKvs, err := execTemplates(kvs, providerCfg.Templates)
		if err != nil {
			return nil, err
		}

		mappingKvs := mapSecretKeys(kvs, providerCfg.Keys)

		// Merge secrets (later providers override earlier ones)
		for _, kv := range append(mappingKvs, tmplKvs...) {
			secrets[kv.Key] = kv.Value
		}
	}

	return secrets, nil
}

// execTemplates returns extra slice of KeyValue slice for given templates.
func execTemplates(in []provider.KeyValue, tmpls []*template.Template) ([]provider.KeyValue, error) {
	if tmpls == nil {
		return []provider.KeyValue{}, nil
	}
	out := make([]provider.KeyValue, 0)
	for _, tmpl := range tmpls {
		var buf bytes.Buffer
		type tmplData struct {
			Env map[string]string
		}
		values := make(map[string]string, len(out))
		for _, kv := range in {
			values[kv.Key] = kv.Value
		}
		if err := tmpl.Execute(&buf, tmplData{Env: values}); err != nil {
			return nil, fmt.Errorf("failed to execute template: %w", err)
		}
		envKey := tmpl.Name()
		v := strings.TrimRight(buf.String(), "\n")
		out = append(out, provider.KeyValue{
			Key:   envKey,
			Value: v,
		})
	}
	return out, nil
}

// mapSecretKeys maps secret data keys according to the provided key mapping
func mapSecretKeys(in []provider.KeyValue, keys map[string]string) []provider.KeyValue {
	if keys == nil {
		return in
	}
	// Map keys according to configuration
	out := make([]provider.KeyValue, 0)
	for _, x := range in {
		k, v := x.Key, x.Value
		targetKey := k

		// Check if there's a specific mapping
		if mappedKey, exists := keys[k]; exists {
			if mappedKey == "==" {
				targetKey = k // Keep same name
			} else {
				targetKey = mappedKey
			}
		} else if len(keys) == 0 {
			// No keys specified means map everything
			targetKey = k
		} else {
			// Skip keys not in the mapping
			continue
		}
		out = append(out, provider.KeyValue{
			Key:   targetKey,
			Value: v,
		})
	}
	return out
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
func Redact(text string, secrets map[string]string) string {
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

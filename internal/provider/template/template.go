package template

import (
	"bytes"
	"fmt"
	"regexp"
	"text/template"

	"github.com/dirathea/sstart/internal/provider"
)

// TemplateProvider implements the provider interface for template-based secret manipulation
type TemplateProvider struct{}

func init() {
	provider.Register("template", func() provider.Provider {
		return &TemplateProvider{}
	})
}

// Name returns the provider name
func (p *TemplateProvider) Name() string {
	return "template"
}

// Fetch fetches secrets by resolving template expressions
// The templates map contains template expressions using dot notation: PG_URI: pgsql://{{.aws_prod.PG_USERNAME}}:{{.aws_prod.PG_PASSWORD}}@{{.aws_generic.PG_HOST}}
func (p *TemplateProvider) Fetch(secretContext provider.SecretContext, mapID string, config map[string]interface{}, keys map[string]string) ([]provider.KeyValue, error) {
	// Get SecretsResolver from secretContext
	resolver := secretContext.SecretsResolver

	// Get templates from config
	templatesRaw, ok := config["templates"]
	if !ok {
		return nil, fmt.Errorf("template provider requires 'templates' field with template expressions")
	}

	templates, ok := templatesRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("template provider 'templates' field must be a map")
	}

	if len(templates) == 0 {
		return nil, fmt.Errorf("template provider requires 'templates' field with template expressions")
	}

	// Get available provider IDs from resolver for validation
	availableProviders := resolver.Map()
	availableProviderIDs := make(map[string]bool)
	for providerID := range availableProviders {
		availableProviderIDs[providerID] = true
	}

	// Resolve each template expression
	kvs := make([]provider.KeyValue, 0, len(templates))
	for targetKey, templateExprRaw := range templates {
		templateExpr, ok := templateExprRaw.(string)
		if !ok {
			return nil, fmt.Errorf("template expression for key '%s' must be a string", targetKey)
		}

		// Validate that all referenced providers are available in the resolver
		referencedProviders := p.extractProviderReferences(templateExpr)
		for _, providerID := range referencedProviders {
			if !availableProviderIDs[providerID] {
				return nil, fmt.Errorf("template for key '%s' references provider '%s' which is not available (not in 'uses' list or provider not found)", targetKey, providerID)
			}
		}

		resolvedValue, err := p.resolveTemplate(templateExpr, resolver)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve template for key '%s': %w", targetKey, err)
		}
		kvs = append(kvs, provider.KeyValue{
			Key:   targetKey,
			Value: resolvedValue,
		})
	}

	return kvs, nil
}

// resolveTemplate resolves a template expression using Go's text/template package
// Template syntax: {{.provider_id.secret_key}} (dot notation, similar to Helm templates)
// Example: {{.aws_prod.PG_USERNAME}} or {{.aws_generic.PG_HOST}}
func (p *TemplateProvider) resolveTemplate(templateStr string, resolver provider.SecretsResolver) (string, error) {
	// Build template data structure from resolver
	// Structure: { "provider_id": { "secret_key": "value", ... }, ... }
	templateData := make(map[string]map[string]string)
	providerSecrets := resolver.Map()
	for providerID, secrets := range providerSecrets {
		templateData[providerID] = secrets
	}

	// Parse the template
	tmpl, err := template.New("secret_template").Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	// Execute the template with the data structure
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, templateData); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// extractProviderReferences extracts all provider IDs referenced in a template string
// Template syntax: {{.provider_id.secret_key}} - extracts "provider_id"
func (p *TemplateProvider) extractProviderReferences(templateStr string) []string {
	// Regex to match {{.provider_id.secret_key}} pattern
	// Matches: {{.provider_id.secret_key}} or {{.provider_id.secret_key}} with optional whitespace
	re := regexp.MustCompile(`\{\{\s*\.([a-zA-Z0-9_-]+)\.`)
	matches := re.FindAllStringSubmatch(templateStr, -1)

	providerIDs := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 {
			providerIDs[match[1]] = true
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(providerIDs))
	for providerID := range providerIDs {
		result = append(result, providerID)
	}

	return result
}

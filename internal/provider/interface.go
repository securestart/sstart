// Package provider defines the interface and registry for secret providers.
package provider

import (
	"context"
	"fmt"
)

// Secrets represents a collection of secret key-value pairs
type Secrets map[string]string

// ProviderSecretsMap represents secrets organized by provider ID
type ProviderSecretsMap map[string]Secrets

// KeyValue represents a secret key-value pair
type KeyValue struct {
	Key   string
	Value string
}

// SecretsResolver provides access to secrets from other providers
// This interface allows providers to access secrets without creating an import cycle
type SecretsResolver interface {
	// Get returns secrets for a specific provider ID
	Get(id string) map[string]string
	// Map returns all provider secrets as a map
	Map() map[string]map[string]string
}

// SecretContext provides context and resolver access to providers
type SecretContext struct {
	Ctx             context.Context
	SecretsResolver SecretsResolver
}

// Provider is the interface that all secret providers must implement
type Provider interface {
	// Name returns the name of the provider
	Name() string

	// Fetch fetches secrets from the provider based on the configuration
	// config contains provider-specific configuration fields (e.g., path, region, endpoint, etc.)
	Fetch(secretContext SecretContext, mapID string, config map[string]interface{}, keys map[string]string) ([]KeyValue, error)
}

// Registry holds all registered providers
var registry = make(map[string]func() Provider)

// Register registers a provider factory function
func Register(kind string, factory func() Provider) {
	registry[kind] = factory
}

// New creates a new provider instance by kind
func New(kind string) (Provider, error) {
	factory, exists := registry[kind]
	if !exists {
		return nil, fmt.Errorf("unknown provider kind: %s", kind)
	}
	return factory(), nil
}

// List returns all registered provider kinds
func List() []string {
	kinds := make([]string, 0, len(registry))
	for kind := range registry {
		kinds = append(kinds, kind)
	}
	return kinds
}

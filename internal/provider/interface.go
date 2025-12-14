// Package provider defines the interface and registry for secret providers.
package provider

import (
	"context"
	"fmt"
)

// KeyValue represents a secret key-value pair
type KeyValue struct {
	Key   string
	Value string
}

// Provider is the interface that all secret providers must implement
type Provider interface {
	// Name returns the name of the provider
	Name() string

	// Fetch fetches secrets from the provider based on the configuration
	// config contains provider-specific configuration fields (e.g., path, region, endpoint, etc.)
	Fetch(ctx context.Context, mapID string, config map[string]interface{}) ([]KeyValue, error)
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

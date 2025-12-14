package dotenv

import (
	"context"
	"fmt"
	"os"

	"github.com/dirathea/sstart/internal/provider"
	"github.com/joho/godotenv"
)

// DotEnvProvider implements the provider interface for .env files
type DotEnvProvider struct{}

func init() {
	provider.Register("dotenv", func() provider.Provider {
		return &DotEnvProvider{}
	})
}

// Name returns the provider name
func (p *DotEnvProvider) Name() string {
	return "dotenv"
}

// Fetch fetches secrets from a .env file
func (p *DotEnvProvider) Fetch(ctx context.Context, mapID string, config map[string]interface{}) ([]provider.KeyValue, error) {
	// Extract path from config
	path, ok := config["path"].(string)
	if !ok || path == "" {
		return nil, fmt.Errorf("dotenv provider requires 'path' field in configuration")
	}

	// Expand path if it contains environment variables
	expandedPath := os.ExpandEnv(path)

	// Load the .env file
	envMap, err := godotenv.Read(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read .env file at '%s': %w", expandedPath, err)
	}

	kvs := make([]provider.KeyValue, 0, len(envMap))
	for k, v := range envMap {
		kvs = append(kvs, provider.KeyValue{
			Key:   k,
			Value: v,
		})
	}

	return kvs, nil
}

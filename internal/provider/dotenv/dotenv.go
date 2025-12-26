package dotenv

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/dirathea/sstart/internal/provider"
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
func (p *DotEnvProvider) Fetch(secretContext provider.SecretContext, mapID string, config map[string]interface{}, keys map[string]string) ([]provider.KeyValue, error) {
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

	// If no keys specified, return all
	if len(keys) == 0 {
		kvs := make([]provider.KeyValue, 0, len(envMap))
		for k, v := range envMap {
			kvs = append(kvs, provider.KeyValue{
				Key:   k,
				Value: v,
			})
		}
		return kvs, nil
	}

	// Map keys according to configuration
	kvs := make([]provider.KeyValue, 0)
	for envKey, targetKey := range keys {
		if value, exists := envMap[envKey]; exists {
			if targetKey == "==" {
				targetKey = envKey // Keep same name
			}
			kvs = append(kvs, provider.KeyValue{
				Key:   targetKey,
				Value: value,
			})
		}
	}

	return kvs, nil
}


package secrets

import (
	"context"

	"github.com/dirathea/sstart/internal/provider"
)

type SecretsResolver struct {
	providerSecrets provider.ProviderSecretsMap
}

func (receiver SecretsResolver) Get(id string) map[string]string {
	return receiver.providerSecrets[id]
}

func (receiver SecretsResolver) Map() map[string]map[string]string {
	result := make(map[string]map[string]string)
	for pid, psecrets := range receiver.providerSecrets {
		result[pid] = psecrets
	}
	return result
}

// SetResolver creates a filtered SecretsResolver that only includes secrets from allowed provider IDs
// If allowedProviderIDs is empty or nil, returns an empty resolver (no access to any secrets)
// This is used for security best practices - providers can only access secrets from explicitly allowed providers
func SetResolver(providerSecrets provider.ProviderSecretsMap, allowedProviderIDs []string) provider.SecretsResolver {
	// If no allowed provider IDs specified, return empty resolver
	if len(allowedProviderIDs) == 0 {
		return SecretsResolver{
			providerSecrets: make(provider.ProviderSecretsMap),
		}
	}

	// Create a map of allowed provider IDs for fast lookup
	allowedMap := make(map[string]bool)
	for _, id := range allowedProviderIDs {
		allowedMap[id] = true
	}

	// Create a filtered copy
	providerSecretsCopy := make(provider.ProviderSecretsMap)
	for pid, psecrets := range providerSecrets {
		// Only include secrets from allowed providers
		if allowedMap[pid] {
			secretsCopy := make(provider.Secrets)
			for k, v := range psecrets {
				secretsCopy[k] = v
			}
			providerSecretsCopy[pid] = secretsCopy
		}
	}

	return SecretsResolver{
		providerSecrets: providerSecretsCopy,
	}
}

func NewEmptySecretContext(ctx context.Context) provider.SecretContext {
	return provider.SecretContext{
		Ctx: ctx,
		SecretsResolver: SecretsResolver{
			providerSecrets: make(provider.ProviderSecretsMap),
		},
	}
}

// NewSecretContext creates a SecretContext with a filtered resolver that only includes secrets from allowed provider IDs
// If allowedProviderIDs is empty or nil, the resolver will be empty (no access to any secrets)
func NewSecretContext(ctx context.Context, providerSecrets provider.ProviderSecretsMap, allowedProviderIDs []string) provider.SecretContext {
	return provider.SecretContext{
		Ctx:             ctx,
		SecretsResolver: SetResolver(providerSecrets, allowedProviderIDs),
	}
}

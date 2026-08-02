// Package keyring reads secrets from the operating system's credential store:
// Keychain on macOS, Credential Manager on Windows, Secret Service on Linux.
package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dirathea/sstart/internal/provider"
	gokeyring "github.com/zalando/go-keyring"
)

// KeyringConfig represents the configuration for the keyring provider
type KeyringConfig struct {
	// Service is the item's service name (required)
	Service string `json:"service" yaml:"service"`
	// User is the item's account name (required)
	User string `json:"user" yaml:"user"`
	// Pointer optionally selects a node inside a JSON payload, as an RFC 6901
	// JSON pointer (for example /claudeAiOauth/accessToken).
	//
	// Not named 'path': in dotenv, infisical and vault that field already means
	// where the secret lives, not where to look inside it.
	Pointer string `json:"pointer,omitempty" yaml:"pointer,omitempty"`
	// Key optionally names the environment variable used when the payload is
	// not a JSON object. Defaults to <PROVIDER_ID>_SECRET.
	Key string `json:"key,omitempty" yaml:"key,omitempty"`
}

// KeyringProvider implements the provider interface for the OS credential store
type KeyringProvider struct{}

func init() {
	provider.Register("keyring", func() provider.Provider {
		return &KeyringProvider{}
	})
}

// Name returns the provider name
func (p *KeyringProvider) Name() string {
	return "keyring"
}

// Fetch reads one item from the OS credential store.
func (p *KeyringProvider) Fetch(secretContext provider.SecretContext, mapID string, config map[string]interface{}, keys map[string]string) ([]provider.KeyValue, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, err
	}
	if cfg.Service == "" {
		return nil, fmt.Errorf("keyring provider requires 'service' field in configuration")
	}
	if cfg.User == "" {
		return nil, fmt.Errorf("keyring provider requires 'user' field in configuration")
	}

	secretValue, err := gokeyring.Get(cfg.Service, cfg.User)
	if err != nil {
		if errors.Is(err, gokeyring.ErrNotFound) {
			return nil, fmt.Errorf("no keyring item for service '%s' and user '%s'", cfg.Service, cfg.User)
		}
		return nil, fmt.Errorf("failed to read from the system keyring for service '%s' and user '%s': %w. "+
			"On Linux this usually means no Secret Service is running, which is common on headless hosts", cfg.Service, cfg.User, err)
	}

	return mapValue(cfg, mapID, keys, secretValue), nil
}

// mapValue turns an item's raw value into variables. A JSON object becomes one
// variable per key, matching what the cloud providers do with a JSON payload;
// anything else becomes a single variable.
//
// A payload that is not JSON at all is emitted verbatim, so a plain password is
// passed through untouched rather than round-tripped.
func mapValue(cfg *KeyringConfig, mapID string, keys map[string]string, raw string) []provider.KeyValue {
	decoded, err := provider.DecodeSecretJSONValue([]byte(raw))
	if err != nil {
		return singleValue(cfg, mapID, raw)
	}

	if object, ok := decoded.(map[string]interface{}); ok {
		return expandObject(object, keys)
	}

	return singleValue(cfg, mapID, provider.StringifyValue(decoded))
}

// expandObject maps each key of a JSON object to a variable, applying the keys
// mapping the same way every other provider does.
func expandObject(object map[string]interface{}, keys map[string]string) []provider.KeyValue {
	kvs := make([]provider.KeyValue, 0, len(object))

	for key, value := range object {
		targetKey := key

		if mappedKey, exists := keys[key]; exists {
			if mappedKey != "==" {
				targetKey = mappedKey
			}
		} else if len(keys) != 0 {
			// Keys were specified and this one is not among them.
			continue
		}

		kvs = append(kvs, provider.KeyValue{
			Key:   targetKey,
			Value: provider.StringifyValue(value),
		})
	}

	return kvs
}

// singleValue emits the one variable used when the payload is not a JSON
// object. The default name follows the convention the cloud providers use for
// their non-JSON payloads; the 'key' config field overrides it.
func singleValue(cfg *KeyringConfig, mapID string, value string) []provider.KeyValue {
	name := cfg.Key
	if name == "" {
		name = strings.ToUpper(strings.ReplaceAll(mapID, "-", "_")) + "_SECRET"
	}

	return []provider.KeyValue{{Key: name, Value: value}}
}

func parseConfig(config map[string]interface{}) (*KeyringConfig, error) {
	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var cfg KeyringConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

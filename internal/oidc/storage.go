package oidc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

const (
	// TokenFileName is the name of the file where tokens are stored (fallback)
	TokenFileName = "tokens.json"
	// ConfigDirName is the name of the directory where sstart stores its configuration
	ConfigDirName = "sstart"
	// KeyringService is the service name used for keyring storage
	KeyringService = "sstart"
	// KeyringUser is the user/account name used for keyring storage
	KeyringUser = "sso-tokens"
)

// StorageBackend represents the type of storage being used
type StorageBackend string

const (
	// StorageBackendKeyring indicates tokens are stored in the system keyring
	StorageBackendKeyring StorageBackend = "keyring"
	// StorageBackendFile indicates tokens are stored in a file
	StorageBackendFile StorageBackend = "file"
)

// storageState tracks which storage backend is being used
type storageState struct {
	backend         StorageBackend
	keyringTested   bool
	keyringDisabled bool
}

var storage = &storageState{}

// getDefaultTokenPath returns the default path for storing tokens (file fallback)
func getDefaultTokenPath() string {
	// Use XDG_CONFIG_HOME if set, otherwise use ~/.config
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			// Fallback to current directory
			return filepath.Join(".", ConfigDirName, TokenFileName)
		}
		configHome = filepath.Join(homeDir, ".config")
	}
	return filepath.Join(configHome, ConfigDirName, TokenFileName)
}

// isKeyringAvailable checks if keyring is available on this system
func isKeyringAvailable() bool {
	if storage.keyringTested {
		return !storage.keyringDisabled
	}

	storage.keyringTested = true

	// Try to access keyring with a test operation
	// We try to get a non-existent key - if keyring is unavailable, it returns a specific error
	_, err := keyring.Get(KeyringService, "test-availability")
	if err != nil {
		// ErrNotFound means keyring is working but key doesn't exist - that's fine
		if err == keyring.ErrNotFound {
			storage.keyringDisabled = false
			return true
		}
		// Any other error means keyring is not available
		storage.keyringDisabled = true
		return false
	}

	storage.keyringDisabled = false
	return true
}

// SetTokenPath sets a custom path for storing tokens (file storage)
func (c *Client) SetTokenPath(path string) {
	c.tokenPath = path
}

// GetTokenPath returns the current token storage path (file storage)
func (c *Client) GetTokenPath() string {
	return c.tokenPath
}

// GetStorageBackend returns the current storage backend being used
func (c *Client) GetStorageBackend() StorageBackend {
	return storage.backend
}

// SaveTokens saves the tokens, trying keyring first then falling back to file
func (c *Client) SaveTokens(tokens *Tokens) error {
	if tokens == nil {
		return fmt.Errorf("tokens cannot be nil")
	}

	// Marshal tokens to JSON
	data, err := json.Marshal(tokens)
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}

	// Try keyring first
	if isKeyringAvailable() {
		err := keyring.Set(KeyringService, KeyringUser, string(data))
		if err == nil {
			storage.backend = StorageBackendKeyring
			// Clean up any old file storage
			_ = os.Remove(c.tokenPath)
			return nil
		}
		// Keyring failed, fall back to file
	}

	// Fall back to file storage
	return c.saveTokensToFile(tokens)
}

// saveTokensToFile saves tokens to a file (fallback method)
func (c *Client) saveTokensToFile(tokens *Tokens) error {
	// Ensure the directory exists
	dir := filepath.Dir(c.tokenPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create token directory: %w", err)
	}

	// Marshal tokens to JSON
	data, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}

	// Write to file with secure permissions (owner read/write only)
	if err := os.WriteFile(c.tokenPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write tokens file: %w", err)
	}

	storage.backend = StorageBackendFile
	return nil
}

// LoadTokens loads the tokens, trying keyring first then falling back to file
func (c *Client) LoadTokens() (*Tokens, error) {
	// Try keyring first
	if isKeyringAvailable() {
		data, err := keyring.Get(KeyringService, KeyringUser)
		if err == nil {
			var tokens Tokens
			if err := json.Unmarshal([]byte(data), &tokens); err != nil {
				// Invalid data in keyring, try to clean up and check file
				_ = keyring.Delete(KeyringService, KeyringUser)
			} else {
				storage.backend = StorageBackendKeyring
				return &tokens, nil
			}
		}
		// Keyring doesn't have tokens or failed, try file
	}

	// Fall back to file storage
	return c.loadTokensFromFile()
}

// loadTokensFromFile loads tokens from a file (fallback method)
func (c *Client) loadTokensFromFile() (*Tokens, error) {
	data, err := os.ReadFile(c.tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no tokens found (not authenticated)")
		}
		return nil, fmt.Errorf("failed to read tokens file: %w", err)
	}

	var tokens Tokens
	if err := json.Unmarshal(data, &tokens); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tokens: %w", err)
	}

	storage.backend = StorageBackendFile
	return &tokens, nil
}

// ClearTokens removes the stored tokens from both keyring and file
func (c *Client) ClearTokens() error {
	var lastErr error

	// Try to clear from keyring
	if isKeyringAvailable() {
		if err := keyring.Delete(KeyringService, KeyringUser); err != nil && err != keyring.ErrNotFound {
			lastErr = fmt.Errorf("failed to remove tokens from keyring: %w", err)
		}
	}

	// Also try to clear from file
	if err := os.Remove(c.tokenPath); err != nil && !os.IsNotExist(err) {
		lastErr = fmt.Errorf("failed to remove tokens file: %w", err)
	}

	return lastErr
}

// TokensExist checks if tokens exist in either keyring or file
func (c *Client) TokensExist() bool {
	// Check keyring first
	if isKeyringAvailable() {
		_, err := keyring.Get(KeyringService, KeyringUser)
		if err == nil {
			return true
		}
	}

	// Check file
	_, err := os.Stat(c.tokenPath)
	return err == nil
}

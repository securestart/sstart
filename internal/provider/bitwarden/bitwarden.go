package bitwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/dirathea/sstart/internal/provider"
)

// BitwardenConfig represents the configuration for personal Bitwarden provider (using CLI REST API)
// The Bitwarden CLI (bw) must be installed and API credentials must be provided
type BitwardenConfig struct {
	// ItemID is the ID of the item in Bitwarden vault (required)
	// Can be found using: bw list items --search "item name" or via Bitwarden web vault
	ItemID string `json:"item_id" yaml:"item_id"`
	// Format specifies how to parse the secret: "note" (JSON), "fields" (key-value pairs), or "login" (username/password)
	Format string `json:"format,omitempty" yaml:"format,omitempty"`
	// BWPath is the path to the Bitwarden CLI binary (optional, defaults to "bw" in PATH)
	BWPath string `json:"bw_path,omitempty" yaml:"bw_path,omitempty"`
	// ServerURL is the Bitwarden server URL (optional, defaults to https://vault.bitwarden.com)
	// For self-hosted instances, set this to your server URL
	ServerURL string `json:"server_url,omitempty" yaml:"server_url,omitempty"`
	// APIPort is the port for the local API server (optional, defaults to 8087)
	APIPort int `json:"api_port,omitempty" yaml:"api_port,omitempty"`
	// APIHostname is the hostname for the local API server (optional, defaults to "localhost")
	APIHostname string `json:"api_hostname,omitempty" yaml:"api_hostname,omitempty"`
}

// BitwardenItem represents a Bitwarden vault item structure from the REST API
type BitwardenItem struct {
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	Type       int                  `json:"type"` // 1 = Login, 2 = Secure Note, etc.
	Login      *BitwardenLogin      `json:"login,omitempty"`
	SecureNote *BitwardenSecureNote `json:"secureNote,omitempty"`
	Fields     []BitwardenField     `json:"fields,omitempty"`
	Notes      string               `json:"notes,omitempty"`
}

// BitwardenLogin represents login credentials
type BitwardenLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URIs     []struct {
		URI string `json:"uri"`
	} `json:"uris,omitempty"`
}

// BitwardenSecureNote represents secure note data
type BitwardenSecureNote struct {
	Type int `json:"type"` // 0 = Generic
}

// BitwardenField represents custom fields in a Bitwarden item
type BitwardenField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  int    `json:"type"` // 0 = Text, 1 = Hidden, 2 = Boolean, 3 = Linked
}

// bwServeProcess manages the bw serve process
type bwServeProcess struct {
	cmd    *exec.Cmd
	port   int
	host   string
	client *http.Client
	apiURL string
}

var (
	bwServeInstance *bwServeProcess
	bwServeMutex    sync.Mutex
)

// BitwardenProvider implements the provider interface for personal Bitwarden (using CLI REST API)
type BitwardenProvider struct{}

func init() {
	provider.Register("bitwarden", func() provider.Provider {
		return &BitwardenProvider{}
	})
}

// Name returns the provider name
func (p *BitwardenProvider) Name() string {
	return "bitwarden"
}

// Fetch fetches secrets from personal Bitwarden vault using REST API
func (p *BitwardenProvider) Fetch(secretContext provider.SecretContext, mapID string, config map[string]interface{}, keys map[string]string) ([]provider.KeyValue, error) {
	ctx := secretContext.Ctx
	// Convert map to strongly typed config struct
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid bitwarden configuration: %w", err)
	}

	// Validate required fields
	if cfg.ItemID == "" {
		return nil, fmt.Errorf("bitwarden provider requires 'item_id' field in configuration")
	}

	// Validate format
	format := strings.ToLower(cfg.Format)
	if format != "" && format != "note" && format != "fields" && format != "both" && format != "login" {
		return nil, fmt.Errorf("bitwarden provider 'format' must be either 'note', 'fields', 'both', or 'login' (got: %s)", cfg.Format)
	}
	if format == "" {
		format = "both" // Default to both format
	}

	// Determine bw path
	bwPath := cfg.BWPath
	if bwPath == "" {
		bwPath = "bw"
	}

	// Check if bw is available
	if err := p.checkBWAvailable(ctx, bwPath); err != nil {
		return nil, fmt.Errorf("bitwarden CLI not available: %w. Please install it from https://bitwarden.com/help/cli/", err)
	}

	// Set server URL if provided
	if cfg.ServerURL != "" {
		if err := p.setServerURL(ctx, bwPath, cfg.ServerURL); err != nil {
			return nil, fmt.Errorf("failed to set Bitwarden server URL: %w", err)
		}
	}

	// Check for API credentials
	clientID := getEnv("BW_CLIENTID")
	clientSecret := getEnv("BW_CLIENTSECRET")
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("bitwarden API credentials required: set BW_CLIENTID and BW_CLIENTSECRET environment variables")
	}

	// Login using API key
	session, err := p.loginWithAPIKey(ctx, bwPath, clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to login with API key: %w", err)
	}

	// Get or start bw serve process
	apiPort := cfg.APIPort
	if apiPort == 0 {
		apiPort = 8087 // Default port
	}
	apiHostname := cfg.APIHostname
	if apiHostname == "" {
		apiHostname = "localhost" // Default hostname
	}

	bwServe, err := p.getOrStartBWServe(ctx, bwPath, apiPort, apiHostname)
	if err != nil {
		return nil, fmt.Errorf("failed to start bw serve: %w", err)
	}

	// Ensure we stop bw serve after fetching (defer cleanup)
	defer func() {
		p.stopBWServe(bwServe)
	}()

	// Get master password for unlocking
	masterPassword := getEnv("BW_PASSWORD")
	if masterPassword == "" {
		return nil, fmt.Errorf("BW_PASSWORD environment variable is required to unlock vault")
	}

	// Unlock the vault via API to get the raw session
	sessionKey, err := p.unlockVaultViaAPI(ctx, bwServe, masterPassword, session)
	if err != nil {
		return nil, fmt.Errorf("failed to unlock vault via API: %w", err)
	}

	// Fetch the item from Bitwarden REST API
	item, err := bwServe.getItemByID(ctx, sessionKey, cfg.ItemID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch item from Bitwarden: %w", err)
	}

	// Parse secrets based on format
	var secretData map[string]interface{}
	switch format {
	case "note":
		// Parse notes as JSON
		if item.Notes == "" {
			return nil, fmt.Errorf("bitwarden item '%s' has no notes for 'note' format", cfg.ItemID)
		}
		if err := json.Unmarshal([]byte(item.Notes), &secretData); err != nil {
			return nil, fmt.Errorf("failed to parse notes as JSON for bitwarden item '%s': %w", cfg.ItemID, err)
		}
	case "login":
		// Extract login credentials
		if item.Login == nil {
			return nil, fmt.Errorf("bitwarden item '%s' is not a login type item", cfg.ItemID)
		}
		secretData = make(map[string]interface{})
		if item.Login.Username != "" {
			secretData["username"] = item.Login.Username
		}
		if item.Login.Password != "" {
			secretData["password"] = item.Login.Password
		}
		// Also include custom fields if any
		for _, field := range item.Fields {
			if field.Type == 0 || field.Type == 1 { // Text or Hidden
				secretData[field.Name] = field.Value
			}
		}
	case "both":
		// Parse both notes and fields, with fields taking precedence
		secretData = make(map[string]interface{})
		
		// First, parse notes as JSON (if available)
		if item.Notes != "" {
			var noteData map[string]interface{}
			if err := json.Unmarshal([]byte(item.Notes), &noteData); err == nil {
				// Add all note data first
				for k, v := range noteData {
					secretData[k] = v
				}
			}
		}
		
		// Then, add fields (which will override any duplicate keys from notes)
		for _, field := range item.Fields {
			if field.Type == 0 || field.Type == 1 { // Text or Hidden
				secretData[field.Name] = field.Value
			}
		}
		
		// Also include login credentials if available
		if item.Login != nil {
			if item.Login.Username != "" {
				secretData["username"] = item.Login.Username
			}
			if item.Login.Password != "" {
				secretData["password"] = item.Login.Password
			}
		}
		
		if len(secretData) == 0 {
			return nil, fmt.Errorf("bitwarden item '%s' has no fields or notes for 'both' format", cfg.ItemID)
		}
	default: // fields
		// Extract custom fields
		secretData = make(map[string]interface{})
		for _, field := range item.Fields {
			if field.Type == 0 || field.Type == 1 { // Text or Hidden
				secretData[field.Name] = field.Value
			}
		}
		// Also include login credentials if available
		if item.Login != nil {
			if item.Login.Username != "" && len(secretData) == 0 {
				// If no custom fields, include username as a field
				secretData["username"] = item.Login.Username
			}
			if item.Login.Password != "" {
				secretData["password"] = item.Login.Password
			}
		}
		// If no fields found, try parsing notes as JSON
		if len(secretData) == 0 && item.Notes != "" {
			var noteData map[string]interface{}
			if err := json.Unmarshal([]byte(item.Notes), &noteData); err == nil {
				secretData = noteData
			}
		}
		if len(secretData) == 0 {
			return nil, fmt.Errorf("bitwarden item '%s' has no fields or notes for 'fields' format", cfg.ItemID)
		}
	}

	// Map keys according to configuration
	kvs := make([]provider.KeyValue, 0)
	for k, v := range secretData {
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

		value := fmt.Sprintf("%v", v)
		kvs = append(kvs, provider.KeyValue{
			Key:   targetKey,
			Value: value,
		})
	}

	return kvs, nil
}

// checkBWAvailable checks if the Bitwarden CLI is available
func (p *BitwardenProvider) checkBWAvailable(ctx context.Context, bwPath string) error {
	cmd := exec.CommandContext(ctx, bwPath, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute bw --version: %w (output: %s)", err, string(output))
	}
	return nil
}

// setServerURL sets the Bitwarden server URL
func (p *BitwardenProvider) setServerURL(ctx context.Context, bwPath, serverURL string) error {
	cmd := exec.CommandContext(ctx, bwPath, "config", "server", serverURL)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set server URL: %w (output: %s)", err, string(output))
	}
	return nil
}

// loginWithAPIKey logs into Bitwarden using API key
// Returns the session key (may be empty if already logged in) and error
func (p *BitwardenProvider) loginWithAPIKey(ctx context.Context, bwPath, clientID, clientSecret string) (string, error) {
	// Check login status first
	statusCmd := exec.CommandContext(ctx, bwPath, "status", "--raw")
	statusOutput, err := statusCmd.Output()
	if err == nil {
		var status map[string]interface{}
		if err := json.Unmarshal(statusOutput, &status); err == nil {
			if statusStr, ok := status["status"].(string); ok {
				if statusStr == "unlocked" || statusStr == "locked" {
					// Already logged in, check if we have a session
					if session := getEnv("BW_SESSION"); session != "" {
						// Verify session is still valid
						verifyCmd := exec.CommandContext(ctx, bwPath, "sync", "--session", session)
						if err := verifyCmd.Run(); err == nil {
							return session, nil
						}
					}
					// If already logged in but no valid session, we'll need to unlock
					// Return empty session to trigger unlock
					return "", nil
				}
			}
		}
	}

	// Login using API key
	loginCmd := exec.CommandContext(ctx, bwPath, "login", "--apikey", "--raw", "--nointeraction")
	loginCmd.Env = os.Environ()
	loginCmd.Env = append(loginCmd.Env, fmt.Sprintf("BW_CLIENTID=%s", clientID))
	loginCmd.Env = append(loginCmd.Env, fmt.Sprintf("BW_CLIENTSECRET=%s", clientSecret))

	output, err := loginCmd.CombinedOutput()
	if err != nil {
		// Check if error is because already logged in
		outputStr := string(output)
		if strings.Contains(outputStr, "already logged in") || strings.Contains(outputStr, "You are already logged in") {
			// Already logged in, check status to get session or proceed to unlock
			statusCmd := exec.CommandContext(ctx, bwPath, "status", "--raw")
			statusOutput, err := statusCmd.Output()
			if err == nil {
				var status map[string]interface{}
				if err := json.Unmarshal(statusOutput, &status); err == nil {
					if statusStr, ok := status["status"].(string); ok {
						if statusStr == "unlocked" || statusStr == "locked" {
							// Already logged in, return empty to trigger unlock
							return "", nil
						}
					}
				}
			}
			// If we can't determine status, return empty to proceed
			return "", nil
		}
		return "", fmt.Errorf("failed to login with API key: %w (output: %s)", err, outputStr)
	}

	session := strings.TrimSpace(string(output))
	if session == "" {
		return "", fmt.Errorf("login did not return a session key. Output: %s", string(output))
	}

	return session, nil
}

// unlockVaultViaAPI unlocks the Bitwarden vault using master password via HTTP API
func (p *BitwardenProvider) unlockVaultViaAPI(ctx context.Context, bwServe *bwServeProcess, masterPassword, session string) (string, error) {
	// Check if already unlocked by checking status
	statusURL := fmt.Sprintf("%s/status", bwServe.apiURL)
	req, err := http.NewRequestWithContext(ctx, "GET", statusURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create status request: %w", err)
	}
	if session != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", session))
	}

	resp, err := bwServe.client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			var status map[string]interface{}
			if err := json.Unmarshal(body, &status); err == nil {
				if statusStr, ok := status["status"].(string); ok {
					if statusStr == "unlocked" {
						// Already unlocked, return existing session or get from environment
						if session != "" {
							return session, nil
						}
						// Try to get session from environment
						if envSession := getEnv("BW_SESSION"); envSession != "" {
							return envSession, nil
						}
					}
				}
			}
		}
	}

	// Unlock the vault via API
	unlockURL := fmt.Sprintf("%s/unlock", bwServe.apiURL)
	unlockData := map[string]string{
		"password": masterPassword,
	}
	unlockJSON, err := json.Marshal(unlockData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal unlock data: %w", err)
	}

	unlockReq, err := http.NewRequestWithContext(ctx, "POST", unlockURL, bytes.NewReader(unlockJSON))
	if err != nil {
		return "", fmt.Errorf("failed to create unlock request: %w", err)
	}
	unlockReq.Header.Set("Content-Type", "application/json")
	if session != "" {
		unlockReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", session))
	}

	unlockResp, err := bwServe.client.Do(unlockReq)
	if err != nil {
		return "", fmt.Errorf("failed to make unlock request: %w", err)
	}
	defer unlockResp.Body.Close()

	if unlockResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(unlockResp.Body)
		return "", fmt.Errorf("unlock API request failed with status %d: %s", unlockResp.StatusCode, string(body))
	}

	body, err := io.ReadAll(unlockResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read unlock response: %w", err)
	}

	var unlockResult map[string]interface{}
	if err := json.Unmarshal(body, &unlockResult); err != nil {
		return "", fmt.Errorf("failed to parse unlock response: %w (body: %s)", err, string(body))
	}

	// Extract session key from response
	// The response structure is: { "success": true, "data": { "raw": "session_key" } }
	var newSession string
	if data, ok := unlockResult["data"].(map[string]interface{}); ok {
		if raw, ok := data["raw"].(string); ok {
			newSession = raw
		}
	}

	// Fallback: try old format fields for backward compatibility
	if newSession == "" {
		if sessionVal, ok := unlockResult["session"].(string); ok {
			newSession = sessionVal
		} else if token, ok := unlockResult["token"].(string); ok {
			newSession = token
		} else if bwSession, ok := unlockResult["BW_SESSION"].(string); ok {
			newSession = bwSession
		}
	}

	// If still no session found, use original session or check environment
	if newSession == "" {
		if session != "" {
			return session, nil
		}
		if envSession := getEnv("BW_SESSION"); envSession != "" {
			return envSession, nil
		}
		return "", fmt.Errorf("unlock response did not contain session key in data.raw. Response: %s", string(body))
	}

	return newSession, nil
}

// stopBWServe stops the bw serve process if it's managed by this provider instance
func (p *BitwardenProvider) stopBWServe(bwServe *bwServeProcess) {
	if bwServe == nil || bwServe.cmd == nil || bwServe.cmd.Process == nil {
		return
	}

	bwServeMutex.Lock()
	defer bwServeMutex.Unlock()

	// Only stop if this is the current instance
	if bwServeInstance == bwServe {
		// Send interrupt signal to gracefully stop the process
		if err := bwServe.cmd.Process.Signal(os.Interrupt); err != nil {
			// If interrupt fails, try kill
			bwServe.cmd.Process.Kill()
		}
		// Wait for process to exit (with timeout)
		done := make(chan error, 1)
		go func() {
			done <- bwServe.cmd.Wait()
		}()

		select {
		case <-done:
			// Process exited
		case <-time.After(2 * time.Second):
			// Timeout - force kill
			bwServe.cmd.Process.Kill()
		}

		// Clear the instance
		bwServeInstance = nil
	}
}

// getOrStartBWServe gets or starts the bw serve process
func (p *BitwardenProvider) getOrStartBWServe(ctx context.Context, bwPath string, port int, hostname string) (*bwServeProcess, error) {
	bwServeMutex.Lock()
	defer bwServeMutex.Unlock()

	// Check if there's already a running instance for this port/hostname
	if bwServeInstance != nil && bwServeInstance.port == port && bwServeInstance.host == hostname {
		// Verify it's still running
		if bwServeInstance.cmd.Process != nil {
			// Check if process is still alive by making a test request to /status
			testURL := fmt.Sprintf("http://%s:%d/status", hostname, port)
			req, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			resp, err := bwServeInstance.client.Do(req)
			if err == nil {
				resp.Body.Close()
				// Server is responding
				if resp.StatusCode == http.StatusOK {
					return bwServeInstance, nil
				}
			}
		}
	}

	// Start new bw serve process
	apiURL := fmt.Sprintf("http://%s:%d", hostname, port)
	cmd := exec.CommandContext(ctx, bwPath, "serve", "--port", fmt.Sprintf("%d", port), "--hostname", hostname)
	cmd.Env = os.Environ()

	// Start the process
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start bw serve: %w", err)
	}

	// Wait for server to be ready
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	maxRetries := 10
	retryDelay := 500 * time.Millisecond
	for i := 0; i < maxRetries; i++ {
		// Try to access the /status endpoint to check if server is ready
		testURL := fmt.Sprintf("%s/status", apiURL)
		req, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)

		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			// Server is responding
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if i < maxRetries-1 {
			time.Sleep(retryDelay)
		} else {
			cmd.Process.Kill()
			cmd.Wait()
			return nil, fmt.Errorf("bw serve did not become ready after %d attempts", maxRetries)
		}
	}

	bwServeInstance = &bwServeProcess{
		cmd:    cmd,
		port:   port,
		host:   hostname,
		client: client,
		apiURL: apiURL,
	}

	return bwServeInstance, nil
}

// getItemByID fetches an item by ID from the REST API
func (bs *bwServeProcess) getItemByID(ctx context.Context, sessionKey, itemID string) (BitwardenItem, error) {
	var item BitwardenItem

	url := fmt.Sprintf("%s/object/item/%s", bs.apiURL, itemID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return item, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sessionKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := bs.client.Do(req)
	if err != nil {
		return item, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return item, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return item, fmt.Errorf("failed to read response: %w", err)
	}

	// Try to parse as wrapped response first (like unlock endpoint)
	var wrappedResponse map[string]interface{}
	if err := json.Unmarshal(body, &wrappedResponse); err == nil {
		// Check if response is wrapped in data field
		if data, ok := wrappedResponse["data"].(map[string]interface{}); ok {
			// Re-marshal the data field and unmarshal into BitwardenItem
			dataJSON, err := json.Marshal(data)
			if err == nil {
				if err := json.Unmarshal(dataJSON, &item); err == nil {
					return item, nil
				}
			}
		}
		// If data field doesn't exist or parsing failed, try direct unmarshal
	}

	// Try direct unmarshal (unwrapped response)
	if err := json.Unmarshal(body, &item); err != nil {
		return item, fmt.Errorf("failed to parse item JSON: %w (body: %s)", err, string(body))
	}

	return item, nil
}

// parseConfig converts a map[string]interface{} to BitwardenConfig
func parseConfig(config map[string]interface{}) (*BitwardenConfig, error) {
	// Use JSON marshaling/unmarshaling for clean conversion
	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var cfg BitwardenConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// getEnvOrDefault gets an environment variable or returns a default value
func getEnvOrDefault(key, defaultValue string) string {
	if val := getEnv(key); val != "" {
		return val
	}
	return defaultValue
}

// getEnv gets an environment variable (mocked for testing)
var getEnv = os.Getenv

// SetGetEnvForTesting allows tests to override the getEnv function
func SetGetEnvForTesting(fn func(string) string) {
	getEnv = fn
}

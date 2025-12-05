package end2end

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
	"testing"
	"time"
)

// bwServeProcess manages the bw serve process for test setup
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

// SetupBitwardenCLI handles login, unlock, and starts bw serve for Bitwarden CLI tests
// This function interacts with the real Bitwarden server via bw CLI
// Required environment variables:
//   - BW_CLIENTID and BW_CLIENTSECRET (for API key login)
//   - BW_PASSWORD (master password for unlocking vault)
//   - BW_SERVER_URL (optional, for self-hosted instances)
//
// Returns the BW_SESSION value and bwServeProcess for making HTTP calls
func SetupBitwardenCLI(ctx context.Context, t *testing.T) (string, *bwServeProcess) {
	t.Helper()

	// Check required environment variables
	clientID := os.Getenv("BW_CLIENTID")
	clientSecret := os.Getenv("BW_CLIENTSECRET")
	if clientID == "" || clientSecret == "" {
		t.Fatalf("BW_CLIENTID and BW_CLIENTSECRET environment variables are required")
	}

	bwPath := os.Getenv("BW_PATH")
	if bwPath == "" {
		bwPath = "bw"
	}

	// Check if bw is available
	if err := checkBWAvailable(ctx, bwPath); err != nil {
		t.Fatalf("Bitwarden CLI not available: %v. Please install it from https://bitwarden.com/help/cli/", err)
	}

	// Set server URL if provided
	if serverURL := os.Getenv("BW_SERVER_URL"); serverURL != "" {
		if err := setServerURL(ctx, bwPath, serverURL); err != nil {
			t.Fatalf("Failed to set Bitwarden server URL: %v", err)
		}
	}

	// Login using API key
	session, err := loginWithAPIKey(ctx, t, bwPath, clientID, clientSecret)
	if err != nil {
		t.Fatalf("Failed to login with API key: %v", err)
	}

	// Start or get bw serve process first
	apiPort := 8087 // Default port
	apiHostname := "localhost"
	bwServe, err := getOrStartBWServe(ctx, t, bwPath, apiPort, apiHostname)
	if err != nil {
		t.Fatalf("Failed to start bw serve: %v", err)
	}

	// Unlock the vault via HTTP API
	masterPassword := os.Getenv("BW_PASSWORD")
	if masterPassword == "" {
		t.Fatalf("BW_PASSWORD environment variable is required to unlock vault")
	}

	unlockedSession, err := unlockVaultViaAPI(ctx, t, bwServe, masterPassword, session)
	if err != nil {
		t.Fatalf("Failed to unlock vault via API: %v", err)
	}

	return unlockedSession, bwServe
}

// checkBWAvailable checks if the Bitwarden CLI is available
func checkBWAvailable(ctx context.Context, bwPath string) error {
	cmd := exec.CommandContext(ctx, bwPath, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute bw --version: %w (output: %s)", err, string(output))
	}
	return nil
}

// setServerURL sets the Bitwarden server URL
func setServerURL(ctx context.Context, bwPath, serverURL string) error {
	cmd := exec.CommandContext(ctx, bwPath, "config", "server", serverURL)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set server URL: %w (output: %s)", err, string(output))
	}
	return nil
}

// loginWithAPIKey logs into Bitwarden using API key
func loginWithAPIKey(ctx context.Context, t *testing.T, bwPath, clientID, clientSecret string) (string, error) {
	t.Helper()

	// Check login status first
	statusCmd := exec.CommandContext(ctx, bwPath, "status", "--raw")
	statusOutput, err := statusCmd.Output()
	if err == nil {
		var status map[string]interface{}
		if err := json.Unmarshal(statusOutput, &status); err == nil {
			if statusStr, ok := status["status"].(string); ok {
				if statusStr == "unlocked" || statusStr == "locked" {
					// Already logged in, check if we have a session
					if session := os.Getenv("BW_SESSION"); session != "" {
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
func unlockVaultViaAPI(ctx context.Context, t *testing.T, bwServe *bwServeProcess, masterPassword, session string) (string, error) {
	t.Helper()

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
						// Already unlocked, return existing session or get from response
						if session != "" {
							return session, nil
						}
						// Try to get session from environment
						if envSession := os.Getenv("BW_SESSION"); envSession != "" {
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
		if envSession := os.Getenv("BW_SESSION"); envSession != "" {
			return envSession, nil
		}
		return "", fmt.Errorf("unlock response did not contain session key in data.raw. Response: %s", string(body))
	}

	return newSession, nil
}

// getOrStartBWServe gets or starts the bw serve process
func getOrStartBWServe(ctx context.Context, t *testing.T, bwPath string, port int, hostname string) (*bwServeProcess, error) {
	t.Helper()

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

	// Capture stdout and stderr for debugging (only used on failure)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

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
			// Final attempt failed - collect all available information
			if cmd.Process != nil {
				cmd.Process.Kill()
				cmd.Wait()
			}
			return nil, fmt.Errorf("bw serve did not become ready after %d attempts. Last error: %v. stdout: %s, stderr: %s", maxRetries, err, stdoutBuf.String(), stderrBuf.String())
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

// stopBWServe stops the bw serve process
func stopBWServe(t *testing.T) {
	t.Helper()

	bwServeMutex.Lock()
	defer bwServeMutex.Unlock()

	if bwServeInstance == nil || bwServeInstance.cmd == nil || bwServeInstance.cmd.Process == nil {
		return
	}

	// Send interrupt signal to gracefully stop the process
	if err := bwServeInstance.cmd.Process.Signal(os.Interrupt); err != nil {
		// If interrupt fails, try kill
		bwServeInstance.cmd.Process.Kill()
	} else {
		// Wait for process to exit (with timeout)
		done := make(chan error, 1)
		go func() {
			done <- bwServeInstance.cmd.Wait()
		}()

		select {
		case <-done:
			// Process exited
		case <-time.After(2 * time.Second):
			// Timeout - force kill
			bwServeInstance.cmd.Process.Kill()
			bwServeInstance.cmd.Wait()
		}
	}

	// Clear the instance
	bwServeInstance = nil
}

// createItemViaAPI creates a Bitwarden vault item using the REST API
func createItemViaAPI(ctx context.Context, t *testing.T, bwServe *bwServeProcess, session string, itemData map[string]interface{}) (string, error) {
	t.Helper()

	// Marshal to JSON
	itemJSON, err := json.Marshal(itemData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal item data: %w", err)
	}

	// Create the item using POST to /object/item
	url := fmt.Sprintf("%s/object/item", bwServe.apiURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(itemJSON))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", session))
	req.Header.Set("Content-Type", "application/json")

	resp, err := bwServe.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var itemResult map[string]interface{}
	if err := json.Unmarshal(body, &itemResult); err != nil {
		return "", fmt.Errorf("failed to parse item JSON: %w (body: %s)", err, string(body))
	}

	// Extract item ID from response
	// The response structure is: { "success": true, "data": { "id": "..." } }
	var itemID string
	if data, ok := itemResult["data"].(map[string]interface{}); ok {
		if id, ok := data["id"].(string); ok {
			itemID = id
		}
	}

	// Fallback: try top-level id for backward compatibility
	if itemID == "" {
		if id, ok := itemResult["id"].(string); ok {
			itemID = id
		}
	}

	if itemID == "" {
		return "", fmt.Errorf("create item response did not contain id field in data.id. Response: %s", string(body))
	}

	return itemID, nil
}

// SetupBitwardenItem creates a Bitwarden vault item using the REST API via bw serve
// This creates an item in the personal vault (not Secrets Manager)
// Always creates a Secure Note (type 2)
// Returns the item ID
// Note: itemType, loginUsername, and loginPassword parameters are kept for backward compatibility but ignored
func SetupBitwardenItem(ctx context.Context, t *testing.T, itemName string, itemType int, noteContent string, fields map[string]string, loginUsername string, loginPassword string) string {
	t.Helper()

	// Ensure we're logged in, unlocked, and bw serve is running
	session, bwServe := SetupBitwardenCLI(ctx, t)

	// Build the item JSON
	// Always use type 2 (Secure Note) for Bitwarden items
	itemData := map[string]interface{}{
		"type": 2, // 2 = Secure Note
		"name": itemName,
		"secureNote": map[string]interface{}{
			"type": 0, // Text field
		},
	}

	if noteContent != "" {
		itemData["notes"] = noteContent
	}

	// Add fields if provided
	if len(fields) > 0 {
		fieldsArray := make([]map[string]interface{}, 0)
		for name, value := range fields {
			fieldsArray = append(fieldsArray, map[string]interface{}{
				"name":  name,
				"value": value,
				"type":  1, // Hidden field
			})
		}
		itemData["fields"] = fieldsArray
	}

	// Create the item via API
	itemID, err := createItemViaAPI(ctx, t, bwServe, session, itemData)
	if err != nil {
		t.Fatalf("Failed to create Bitwarden item: %v", err)
	}

	// Stop bw serve process after creating the test secret
	stopBWServe(t)

	return itemID
}

// SetupBitwardenPersonalVaultItem creates a test item in Bitwarden personal vault with fields format
// This is a convenience wrapper around SetupBitwardenItem for personal vault items
// Always creates a Secure Note (type 2)
func SetupBitwardenPersonalVaultItem(ctx context.Context, t *testing.T, itemName string, noteContent string, fields map[string]string) (string, string) {
	t.Helper()

	// Create a Secure Note (type 2) with fields
	itemID := SetupBitwardenItem(ctx, t, itemName, 2, noteContent, fields, "", "")

	// Get the session for return
	session, _ := SetupBitwardenCLI(ctx, t)

	return itemID, session
}

package end2end

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

// DopplerClient wraps HTTP client and API configuration for Doppler
type DopplerClient struct {
	client    *http.Client
	apiHost   string
	authToken string
}

// DopplerSecretsUpdateRequest represents the request body for updating secrets
// According to Doppler API: https://docs.doppler.com/reference/secrets-update
// The body format is:
//
//	{
//	  "project": "PROJECT_NAME",
//	  "config": "CONFIG_NAME",
//	  "secrets": {
//	    "SECRET_NAME": "secret_value"
//	  }
//	}
type DopplerSecretsUpdateRequest struct {
	Project string            `json:"project"`
	Config  string            `json:"config"`
	Secrets map[string]string `json:"secrets"`
}

// SetupDopplerClient creates and authenticates a Doppler client for testing
func SetupDopplerClient(ctx context.Context, t *testing.T) *DopplerClient {
	t.Helper()

	// Check for required environment variable
	authToken := os.Getenv("DOPPLER_TOKEN")
	if authToken == "" {
		t.Skipf("Skipping test: DOPPLER_TOKEN environment variable is required")
	}

	// Get API host from environment variable (optional, defaults to https://api.doppler.com)
	apiHost := os.Getenv("DOPPLER_API_HOST")
	if apiHost == "" {
		apiHost = "https://api.doppler.com"
	}

	return &DopplerClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiHost:   apiHost,
		authToken: authToken,
	}
}

// GetDopplerTestProject returns the test project name from environment variable
func GetDopplerTestProject(t *testing.T) string {
	t.Helper()

	project := os.Getenv("SSTART_E2E_DOPPLER_PROJECT")
	if project == "" {
		t.Skipf("Skipping test: SSTART_E2E_DOPPLER_PROJECT environment variable is required")
	}

	return project
}

// GetDopplerTestConfig returns the test config/environment name from environment variable
func GetDopplerTestConfig(t *testing.T) string {
	t.Helper()

	config := os.Getenv("SSTART_E2E_DOPPLER_CONFIG")
	if config == "" {
		t.Skipf("Skipping test: SSTART_E2E_DOPPLER_CONFIG environment variable is required")
	}

	return config
}

// SetupDopplerSecretsBatch creates or updates multiple secrets in Doppler
func SetupDopplerSecretsBatch(ctx context.Context, t *testing.T, client *DopplerClient, project, config string, secrets map[string]string) {
	t.Helper()

	if len(secrets) == 0 {
		return
	}

	apiURL := fmt.Sprintf("%s/v3/configs/config/secrets", client.apiHost)
	updateReq := DopplerSecretsUpdateRequest{
		Project: project,
		Config:  config,
		Secrets: secrets,
	}

	jsonData, err := json.Marshal(updateReq)
	if err != nil {
		t.Fatalf("Failed to marshal secrets update request: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.authToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Make HTTP request
	resp, err := client.client.Do(req)
	if err != nil {
		t.Fatalf("Failed to update secrets in Doppler: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Doppler API returned status %d: %s", resp.StatusCode, string(body))
	}
}

// DeleteDopplerSecret deletes a secret from Doppler using the DELETE endpoint
// According to Doppler API: https://docs.doppler.com/reference/configs-config-secret-delete
func DeleteDopplerSecret(ctx context.Context, t *testing.T, client *DopplerClient, project, config, secretName string) {
	t.Helper()

	// Build API URL for deleting a secret
	apiURL := fmt.Sprintf("%s/v3/configs/config/secret?project=%s&config=%s&name=%s",
		client.apiHost, url.QueryEscape(project), url.QueryEscape(config), url.QueryEscape(secretName))

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "DELETE", apiURL, nil)
	if err != nil {
		t.Logf("Note: Could not create delete request for secret '%s': %v", secretName, err)
		return
	}

	// Set headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.authToken))
	req.Header.Set("Accept", "application/json")

	// Make HTTP request
	resp, err := client.client.Do(req)
	if err != nil {
		t.Logf("Note: Could not delete secret '%s' from Doppler: %v", secretName, err)
		return
	}
	defer resp.Body.Close()

	// Log but don't fail - the secret might not exist, which is fine
	// Accept both 200 OK and 204 No Content as success responses
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Logf("Note: Could not delete secret '%s' from Doppler (status %d): %s", secretName, resp.StatusCode, string(body))
	}
}

// DeleteDopplerSecretsBatch deletes multiple secrets from Doppler (if they exist)
func DeleteDopplerSecretsBatch(ctx context.Context, t *testing.T, client *DopplerClient, project, config string, secretNames []string) {
	t.Helper()

	if len(secretNames) == 0 {
		return
	}

	// Delete each secret individually
	for _, secretName := range secretNames {
		DeleteDopplerSecret(ctx, t, client, project, config, secretName)
	}
}

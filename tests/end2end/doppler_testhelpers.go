package end2end

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// DopplerSecret represents a secret in Doppler
type DopplerSecret struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// DopplerSecretUpdate represents a secret update request
type DopplerSecretUpdate struct {
	Name  string `json:"name"`
	Value string `json:"value"`
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

// SetupDopplerSecret creates or updates a secret in Doppler for testing
func SetupDopplerSecret(ctx context.Context, t *testing.T, client *DopplerClient, project, config, secretName, secretValue string) {
	t.Helper()

	// Build API URL for updating a secret
	apiURL := fmt.Sprintf("%s/v3/configs/config/secrets", client.apiHost)

	// Create request body - Doppler expects an array of secret updates
	updateReq := []DopplerSecretUpdate{
		{
			Name:  secretName,
			Value: secretValue,
		},
	}

	jsonData, err := json.Marshal(updateReq)
	if err != nil {
		t.Fatalf("Failed to marshal secret update request: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "PATCH", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.authToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add query parameters
	q := req.URL.Query()
	q.Add("project", project)
	q.Add("config", config)
	req.URL.RawQuery = q.Encode()

	// Make HTTP request
	resp, err := client.client.Do(req)
	if err != nil {
		t.Fatalf("Failed to update secret in Doppler: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Doppler API returned status %d: %s", resp.StatusCode, string(body))
	}
}

// SetupDopplerSecretsBatch creates or updates multiple secrets in Doppler
// secrets is a map of secretName -> secretValue
func SetupDopplerSecretsBatch(ctx context.Context, t *testing.T, client *DopplerClient, project, config string, secrets map[string]string) {
	t.Helper()

	if len(secrets) == 0 {
		return
	}

	// Build API URL for updating secrets
	apiURL := fmt.Sprintf("%s/v3/configs/config/secrets", client.apiHost)

	// Build request body with all secrets
	secretUpdates := make([]DopplerSecretUpdate, 0, len(secrets))
	for name, value := range secrets {
		secretUpdates = append(secretUpdates, DopplerSecretUpdate{
			Name:  name,
			Value: value,
		})
	}

	jsonData, err := json.Marshal(secretUpdates)
	if err != nil {
		t.Fatalf("Failed to marshal secrets update request: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "PATCH", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.authToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add query parameters
	q := req.URL.Query()
	q.Add("project", project)
	q.Add("config", config)
	req.URL.RawQuery = q.Encode()

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

// DeleteDopplerSecret deletes a secret from Doppler by setting it to empty value
// Note: Doppler doesn't have a direct DELETE endpoint, so we set the value to empty
func DeleteDopplerSecret(ctx context.Context, t *testing.T, client *DopplerClient, project, config, secretName string) {
	t.Helper()

	// Build API URL for updating a secret
	apiURL := fmt.Sprintf("%s/v3/configs/config/secrets", client.apiHost)

	// Create request body - set secret value to empty string to effectively "delete" it
	updateReq := []DopplerSecretUpdate{
		{
			Name:  secretName,
			Value: "", // Empty value to remove the secret
		},
	}

	jsonData, err := json.Marshal(updateReq)
	if err != nil {
		t.Logf("Note: Could not marshal delete request for secret '%s': %v", secretName, err)
		return
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "PATCH", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		t.Logf("Note: Could not create delete request for secret '%s': %v", secretName, err)
		return
	}

	// Set headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.authToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add query parameters
	q := req.URL.Query()
	q.Add("project", project)
	q.Add("config", config)
	req.URL.RawQuery = q.Encode()

	// Make HTTP request
	resp, err := client.client.Do(req)
	if err != nil {
		t.Logf("Note: Could not delete secret '%s' from Doppler: %v", secretName, err)
		return
	}
	defer resp.Body.Close()

	// Log but don't fail - the secret might not exist, which is fine
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Logf("Note: Could not delete secret '%s' from Doppler (status %d): %s", secretName, resp.StatusCode, string(body))
	}
}

// DeleteDopplerSecretsBatch deletes multiple secrets from Doppler (if they exist)
// secretNames is a slice of secret names to delete
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

// VerifyDopplerSecretExists checks if a secret exists in Doppler
func VerifyDopplerSecretExists(ctx context.Context, t *testing.T, client *DopplerClient, project, config, secretName string) {
	t.Helper()

	// Build API URL for downloading secrets
	apiURL := fmt.Sprintf("%s/v3/configs/config/secrets/download?format=json&project=%s&config=%s",
		client.apiHost, project, config)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.authToken))
	req.Header.Set("Accept", "application/json")

	// Make HTTP request
	resp, err := client.client.Do(req)
	if err != nil {
		t.Fatalf("Failed to fetch secrets from Doppler: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Skipf("Skipping test: Failed to fetch secrets from Doppler (status %d): %s", resp.StatusCode, string(body))
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// Parse JSON response
	var secretData map[string]interface{}
	if err := json.Unmarshal(body, &secretData); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	// Check if secret exists
	if _, exists := secretData[secretName]; !exists {
		t.Skipf("Skipping test: Secret '%s' does not exist in project '%s' config '%s'. "+
			"Please create it beforehand in your Doppler project.", secretName, project, config)
	}
}


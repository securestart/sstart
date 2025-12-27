package end2end

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dirathea/sstart/internal/config"
	"github.com/dirathea/sstart/internal/oidc"
	_ "github.com/dirathea/sstart/internal/provider/vault"
	"github.com/dirathea/sstart/internal/secrets"
)

// Tests for SSO integration with a real OIDC provider
// These tests require the following environment variables:
//
// Required:
//   - SSTART_E2E_SSO_ISSUER: The OIDC issuer URL (e.g., "https://your-instance.zitadel.cloud")
//   - SSTART_E2E_SSO_CLIENT_ID: The OIDC client ID
//   - SSTART_E2E_SSO_CLIENT_SECRET: The OIDC client secret (set via SSTART_SSO_SECRET env var at runtime)
//
// Optional:
//   - SSTART_E2E_SSO_AUDIENCE: The expected audience claim (defaults to client ID)
//
// Authentication flows:
//   - Interactive (browser): Only requires client ID, user authenticates via browser
//   - Non-interactive (CI): Requires client ID + client secret, uses client credentials flow

// TestE2E_SSO_OIDCClient_HasClientCredentials tests the detection of client credentials capability
func TestE2E_SSO_OIDCClient_HasClientCredentials(t *testing.T) {
	// Test case 1: Client with both ID and secret should have credentials
	cfgWithSecret := &config.OIDCConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Issuer:       "https://example.com",
		Scopes:       []string{"openid"},
	}

	clientWithSecret, err := oidc.NewClient(cfgWithSecret)
	if err != nil {
		t.Fatalf("Failed to create OIDC client with secret: %v", err)
	}

	if !clientWithSecret.HasClientCredentials() {
		t.Error("Expected client with secret to have client credentials capability")
	}

	// Test case 2: Client with only ID (PKCE) should NOT have credentials
	cfgWithoutSecret := &config.OIDCConfig{
		ClientID: "test-client-id",
		Issuer:   "https://example.com",
		Scopes:   []string{"openid"},
	}

	clientWithoutSecret, err := oidc.NewClient(cfgWithoutSecret)
	if err != nil {
		t.Fatalf("Failed to create OIDC client without secret: %v", err)
	}

	if clientWithoutSecret.HasClientCredentials() {
		t.Error("Expected client without secret to NOT have client credentials capability")
	}

	t.Logf("Successfully verified HasClientCredentials detection")
}

// TestE2E_SSO_OIDCClient_TokenStorage tests the OIDC client token storage functionality
func TestE2E_SSO_OIDCClient_TokenStorage(t *testing.T) {
	// Create OIDC config with test values (no real provider needed for storage test)
	cfg := &config.OIDCConfig{
		ClientID: "test-client-id",
		Issuer:   "https://example.com",
		Scopes:   []string{"openid", "profile", "email"},
	}

	// Create OIDC client
	client, err := oidc.NewClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create OIDC client: %v", err)
	}

	// IMPORTANT: Register cleanup FIRST to ensure tokens are cleared even if test fails
	// This prevents test pollution - tokens in keyring are global and shared across all OIDC clients
	t.Cleanup(func() {
		t.Log("Cleanup: Clearing any leftover tokens from token storage test")
		if err := client.ClearTokens(); err != nil {
			t.Logf("Cleanup warning: Failed to clear tokens: %v", err)
		}
	})

	// Test token storage
	testTokens := &oidc.Tokens{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		IDToken:      "test-id-token",
		TokenType:    "Bearer",
	}

	// Save tokens
	err = client.SaveTokens(testTokens)
	if err != nil {
		t.Fatalf("Failed to save tokens: %v", err)
	}

	// Load tokens
	loadedTokens, err := client.LoadTokens()
	if err != nil {
		t.Fatalf("Failed to load tokens: %v", err)
	}

	// Verify
	if loadedTokens.AccessToken != testTokens.AccessToken {
		t.Errorf("AccessToken mismatch: expected '%s', got '%s'", testTokens.AccessToken, loadedTokens.AccessToken)
	}
	if loadedTokens.RefreshToken != testTokens.RefreshToken {
		t.Errorf("RefreshToken mismatch: expected '%s', got '%s'", testTokens.RefreshToken, loadedTokens.RefreshToken)
	}
	if loadedTokens.IDToken != testTokens.IDToken {
		t.Errorf("IDToken mismatch: expected '%s', got '%s'", testTokens.IDToken, loadedTokens.IDToken)
	}

	// Log storage backend being used
	t.Logf("Token storage backend: %s", client.GetStorageBackend())

	// Clear tokens
	err = client.ClearTokens()
	if err != nil {
		t.Fatalf("Failed to clear tokens: %v", err)
	}

	// Verify tokens are cleared
	if client.TokensExist() {
		t.Error("Tokens should not exist after clearing")
	}

	t.Logf("Successfully tested token storage functionality")
}

// TestE2E_SSO_ClientCredentialsFlow tests the client credentials flow for non-interactive authentication
// This test requires a confidential client with client_credentials grant type enabled
func TestE2E_SSO_ClientCredentialsFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires real OIDC provider")
	}
	ctx := context.Background()

	// Get SSO configuration from environment
	issuer, clientID, clientSecret, audience := GetSSOTestConfig(t)

	// Clear any leftover tokens from previous tests (shared keyring)
	tempClient, err := oidc.NewClient(&config.OIDCConfig{
		ClientID: "cleanup-client",
		Issuer:   "https://cleanup.example.com",
		Scopes:   []string{"openid"},
	})
	if err == nil && tempClient.TokensExist() {
		_ = tempClient.ClearTokens()
	}

	// Verify OIDC discovery endpoint is accessible
	VerifyOIDCDiscovery(t, issuer)

	// Set the client secret via environment variable (this is the only supported way)
	t.Setenv(oidc.SSOSecretEnvVar, clientSecret)

	// Setup OpenBao container
	openbaoContainer := SetupOpenBao(ctx, t)
	defer func() {
		if err := openbaoContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate OpenBao container: %v", err)
		}
	}()

	// Create a policy that allows reading secrets
	policyHCL := `
path "secret/data/*" {
  capabilities = ["read", "list"]
}
`
	SetupOpenBaoPolicy(ctx, t, openbaoContainer, "client-creds-reader", policyHCL)

	// Setup JWT auth with OIDC discovery from the real provider
	SetupOpenBaoJWTAuthWithOIDCDiscovery(ctx, t, openbaoContainer, issuer, audience, "client-creds-role", []string{"client-creds-reader"})

	// Write test secret to OpenBao
	secretPath := "client-creds-test/config"
	secretData := map[string]interface{}{
		"CLIENT_CREDS_API_KEY": "client-creds-secret-api-key-12345",
		"CLIENT_CREDS_SECRET":  "client-creds-secret-value",
	}
	SetupOpenBaoSecret(ctx, t, openbaoContainer, secretPath, secretData)

	// Create temporary config file with SSO configuration (client secret comes from env var)
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
sso:
  oidc:
    clientId: %s
    issuer: %s
    scopes:
      - openid
      - profile
      - email

providers:
  - kind: vault
    id: openbao-client-creds-test
    path: %s
    address: %s
    mount: secret
    auth:
      method: jwt
      role: client-creds-role
`, clientID, issuer, secretPath, openbaoContainer.Address)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load config
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify the OIDC client detects it has client credentials
	oidcClient, err := oidc.NewClient(cfg.SSO.OIDC)
	if err != nil {
		t.Fatalf("Failed to create OIDC client: %v", err)
	}

	if !oidcClient.HasClientCredentials() {
		t.Fatalf("Expected OIDC client to have client credentials, but it does not")
	}

	// Create collector and collect secrets using client credentials flow
	collector := secrets.NewCollector(cfg)
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets using client credentials flow: %v", err)
	}

	// Verify secrets
	expectedSecrets := map[string]string{
		"CLIENT_CREDS_API_KEY": "client-creds-secret-api-key-12345",
		"CLIENT_CREDS_SECRET":  "client-creds-secret-value",
	}

	for key, expectedValue := range expectedSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s': expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}
}

// TestE2E_SSO_ClientCredentialsFlow_WithCustomAuthMount tests client credentials with a custom JWT auth mount path
func TestE2E_SSO_ClientCredentialsFlow_WithCustomAuthMount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires real OIDC provider")
	}
	ctx := context.Background()

	// Get SSO configuration from environment
	issuer, clientID, clientSecret, audience := GetSSOTestConfig(t)

	// Clear any leftover tokens from previous tests (shared keyring)
	tempClient, err := oidc.NewClient(&config.OIDCConfig{
		ClientID: "cleanup-client",
		Issuer:   "https://cleanup.example.com",
		Scopes:   []string{"openid"},
	})
	if err == nil && tempClient.TokensExist() {
		_ = tempClient.ClearTokens()
	}

	// Set the client secret via environment variable
	t.Setenv(oidc.SSOSecretEnvVar, clientSecret)

	// Setup OpenBao container
	openbaoContainer := SetupOpenBao(ctx, t)
	defer func() {
		if err := openbaoContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate OpenBao container: %v", err)
		}
	}()

	// Create a policy
	policyHCL := `
path "secret/data/*" {
  capabilities = ["read", "list"]
}
`
	SetupOpenBaoPolicy(ctx, t, openbaoContainer, "custom-sso-reader", policyHCL)

	// Enable JWT auth at a custom mount path
	_, err = openbaoContainer.Client.Logical().Write("sys/auth/custom-sso", map[string]interface{}{
		"type":        "jwt",
		"description": "Custom SSO JWT auth method",
	})
	if err != nil {
		t.Logf("Note: Custom JWT auth method might already be enabled: %v", err)
	}

	// Configure custom JWT auth with OIDC discovery
	_, err = openbaoContainer.Client.Logical().Write("auth/custom-sso/config", map[string]interface{}{
		"oidc_discovery_url": issuer,
		"default_role":       "custom-sso-role",
	})
	if err != nil {
		t.Fatalf("Failed to configure custom JWT auth: %v", err)
	}

	// Create role for custom JWT auth
	_, err = openbaoContainer.Client.Logical().Write("auth/custom-sso/role/custom-sso-role", map[string]interface{}{
		"role_type":       "jwt",
		"user_claim":      "sub",
		"policies":        []string{"custom-sso-reader"},
		"bound_audiences": []string{audience},
	})
	if err != nil {
		t.Fatalf("Failed to create custom JWT role: %v", err)
	}

	// Write test secret
	secretPath := "custom-sso-test/config"
	secretData := map[string]interface{}{
		"CUSTOM_SSO_SECRET": "custom-sso-secret-value",
	}
	SetupOpenBaoSecret(ctx, t, openbaoContainer, secretPath, secretData)

	// Create config file with custom auth mount
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
sso:
  oidc:
    clientId: %s
    issuer: %s
    scopes:
      - openid
      - profile

providers:
  - kind: vault
    id: openbao-custom-sso-test
    path: %s
    address: %s
    mount: secret
    auth:
      method: jwt
      mount: custom-sso
      role: custom-sso-role
`, clientID, issuer, secretPath, openbaoContainer.Address)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load config
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Collect secrets using client credentials flow
	collector := secrets.NewCollector(cfg)
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify
	if collectedSecrets["CUSTOM_SSO_SECRET"] != "custom-sso-secret-value" {
		t.Errorf("Expected CUSTOM_SSO_SECRET to be 'custom-sso-secret-value', got '%s'", collectedSecrets["CUSTOM_SSO_SECRET"])
	}

	t.Logf("Successfully collected secrets using custom SSO auth mount with client credentials flow")
}

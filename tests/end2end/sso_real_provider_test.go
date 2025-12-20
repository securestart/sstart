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
//   - SSTART_E2E_SSO_CLIENT_SECRET: The OIDC client secret (for confidential clients)
//   - SSTART_E2E_SSO_ID_TOKEN: A valid ID token from the OIDC provider (for non-interactive testing)
//
// Optional:
//   - SSTART_E2E_SSO_AUDIENCE: The expected audience claim (defaults to client ID)
//
// The ID token can be obtained by running sstart manually with --force-auth
// and then reading the token from keyring or ~/.config/sstart/tokens.json

// GetSSOTestConfig returns the SSO test configuration from environment variables
func GetSSOTestConfig(t *testing.T) (issuer, clientID, clientSecret, idToken, audience string) {
	t.Helper()

	issuer = os.Getenv("SSTART_E2E_SSO_ISSUER")
	if issuer == "" {
		t.Skipf("Skipping test: SSTART_E2E_SSO_ISSUER environment variable is required")
	}

	clientID = os.Getenv("SSTART_E2E_SSO_CLIENT_ID")
	if clientID == "" {
		t.Skipf("Skipping test: SSTART_E2E_SSO_CLIENT_ID environment variable is required")
	}

	clientSecret = os.Getenv("SSTART_E2E_SSO_CLIENT_SECRET")
	// Client secret is optional for PKCE-enabled clients

	idToken = os.Getenv("SSTART_E2E_SSO_ID_TOKEN")
	if idToken == "" {
		t.Skipf("Skipping test: SSTART_E2E_SSO_ID_TOKEN environment variable is required. " +
			"Obtain a token by running: sstart --force-auth show")
	}

	audience = os.Getenv("SSTART_E2E_SSO_AUDIENCE")
	if audience == "" {
		audience = clientID // Default to client ID
	}

	return
}

// SetupOpenBaoJWTAuthWithOIDCDiscovery configures JWT auth in OpenBao using OIDC discovery
func SetupOpenBaoJWTAuthWithOIDCDiscovery(ctx context.Context, t *testing.T, container *OpenBaoContainer, issuer, audience, role string, policies []string) {
	t.Helper()

	// Enable JWT auth method
	_, err := container.Client.Logical().Write("sys/auth/jwt", map[string]interface{}{
		"type":        "jwt",
		"description": "JWT auth method for SSO",
	})
	if err != nil {
		// If already enabled, that's okay
		if err.Error() != "path is already in use at jwt/" {
			t.Logf("Note: JWT auth method might already be enabled: %v", err)
		}
	}

	// Configure JWT auth with OIDC discovery
	jwtConfig := map[string]interface{}{
		"oidc_discovery_url": issuer,
		"default_role":       role,
	}
	_, err = container.Client.Logical().Write("auth/jwt/config", jwtConfig)
	if err != nil {
		t.Fatalf("Failed to configure JWT auth with OIDC discovery: %v", err)
	}

	// Create role for JWT auth
	roleConfig := map[string]interface{}{
		"role_type":       "jwt",
		"user_claim":      "sub",
		"policies":        policies,
		"bound_audiences": []string{audience},
	}

	_, err = container.Client.Logical().Write(fmt.Sprintf("auth/jwt/role/%s", role), roleConfig)
	if err != nil {
		t.Fatalf("Failed to create JWT role: %v", err)
	}

	t.Logf("Configured OpenBao JWT auth with OIDC discovery from %s", issuer)
}

// SetupOpenBaoPolicy creates a policy in OpenBao
func SetupOpenBaoPolicy(ctx context.Context, t *testing.T, container *OpenBaoContainer, policyName, policyHCL string) {
	t.Helper()

	_, err := container.Client.Logical().Write(fmt.Sprintf("sys/policies/acl/%s", policyName), map[string]interface{}{
		"policy": policyHCL,
	})
	if err != nil {
		t.Fatalf("Failed to create OpenBao policy: %v", err)
	}
}

// TestE2E_SSO_OpenBao_WithRealProvider tests SSO authentication with OpenBao using a real OIDC provider
func TestE2E_SSO_OpenBao_WithRealProvider(t *testing.T) {
	ctx := context.Background()

	// Get SSO configuration from environment
	issuer, clientID, _, idToken, audience := GetSSOTestConfig(t)

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
	SetupOpenBaoPolicy(ctx, t, openbaoContainer, "sso-reader", policyHCL)

	// Setup JWT auth with OIDC discovery from the real provider
	SetupOpenBaoJWTAuthWithOIDCDiscovery(ctx, t, openbaoContainer, issuer, audience, "sso-role", []string{"sso-reader"})

	// Write test secret to OpenBao
	secretPath := "sso-test/config"
	secretData := map[string]interface{}{
		"SSO_API_KEY":     "sso-secret-api-key-12345",
		"SSO_DB_PASSWORD": "sso-secret-db-password",
		"SSO_CONFIG":      "sso-config-value",
	}
	SetupOpenBaoSecret(ctx, t, openbaoContainer, secretPath, secretData)

	// Create temporary config file with SSO configuration
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
    id: openbao-sso-test
    path: %s
    address: %s
    mount: secret
    auth:
      method: jwt
      role: sso-role
`, clientID, issuer, secretPath, openbaoContainer.Address)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load config
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Inject the real ID token into the provider config
	// In normal usage, this is done by the SSO authentication flow
	for i := range cfg.Providers {
		cfg.Providers[i].Config["_sso_id_token"] = idToken
	}

	// Create collector and collect secrets
	collector := secrets.NewCollector(cfg)
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify secrets
	expectedSecrets := map[string]string{
		"SSO_API_KEY":     "sso-secret-api-key-12345",
		"SSO_DB_PASSWORD": "sso-secret-db-password",
		"SSO_CONFIG":      "sso-config-value",
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

	if len(collectedSecrets) != len(expectedSecrets) {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", len(expectedSecrets), len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from OpenBao using real SSO provider", len(collectedSecrets))
}

// TestE2E_SSO_OpenBao_WithCustomAuthMount tests SSO with a custom JWT auth mount path
func TestE2E_SSO_OpenBao_WithCustomAuthMount(t *testing.T) {
	ctx := context.Background()

	// Get SSO configuration from environment
	issuer, clientID, _, idToken, audience := GetSSOTestConfig(t)

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
	_, err := openbaoContainer.Client.Logical().Write("sys/auth/custom-sso", map[string]interface{}{
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

	// Inject the real ID token
	for i := range cfg.Providers {
		cfg.Providers[i].Config["_sso_id_token"] = idToken
	}

	// Collect secrets
	collector := secrets.NewCollector(cfg)
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify
	if collectedSecrets["CUSTOM_SSO_SECRET"] != "custom-sso-secret-value" {
		t.Errorf("Expected CUSTOM_SSO_SECRET to be 'custom-sso-secret-value', got '%s'", collectedSecrets["CUSTOM_SSO_SECRET"])
	}

	t.Logf("Successfully collected secrets using custom SSO auth mount")
}

// TestE2E_SSO_OIDCClient_TokenStorage tests the OIDC client token storage functionality
func TestE2E_SSO_OIDCClient_TokenStorage(t *testing.T) {
	// Get SSO configuration from environment
	issuer, clientID, _, _, _ := GetSSOTestConfig(t)

	// Create OIDC config
	cfg := &config.OIDCConfig{
		ClientID: clientID,
		Issuer:   issuer,
		Scopes:   []string{"openid", "profile", "email"},
	}

	// Create OIDC client
	client, err := oidc.NewClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create OIDC client: %v", err)
	}

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

// TestE2E_SSO_FullFlow_WithForceAuth tests the full SSO flow including force auth flag
func TestE2E_SSO_FullFlow_WithForceAuth(t *testing.T) {
	ctx := context.Background()

	// Get SSO configuration from environment
	issuer, clientID, _, idToken, audience := GetSSOTestConfig(t)

	// Setup OpenBao container
	openbaoContainer := SetupOpenBao(ctx, t)
	defer func() {
		if err := openbaoContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate OpenBao container: %v", err)
		}
	}()

	// Setup policy and JWT auth
	policyHCL := `
path "secret/data/*" {
  capabilities = ["read", "list"]
}
`
	SetupOpenBaoPolicy(ctx, t, openbaoContainer, "force-auth-reader", policyHCL)
	SetupOpenBaoJWTAuthWithOIDCDiscovery(ctx, t, openbaoContainer, issuer, audience, "force-auth-role", []string{"force-auth-reader"})

	// Write test secret
	secretPath := "force-auth-test/config"
	secretData := map[string]interface{}{
		"FORCE_AUTH_SECRET": "force-auth-secret-value",
	}
	SetupOpenBaoSecret(ctx, t, openbaoContainer, secretPath, secretData)

	// Create config file
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
    id: force-auth-test
    path: %s
    address: %s
    mount: secret
    auth:
      method: jwt
      role: force-auth-role
`, clientID, issuer, secretPath, openbaoContainer.Address)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load config
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Inject the real ID token
	for i := range cfg.Providers {
		cfg.Providers[i].Config["_sso_id_token"] = idToken
	}

	// Test with force auth enabled
	collector := secrets.NewCollector(cfg, secrets.WithForceAuth(true))
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets with force auth: %v", err)
	}

	// Verify
	if collectedSecrets["FORCE_AUTH_SECRET"] != "force-auth-secret-value" {
		t.Errorf("Expected FORCE_AUTH_SECRET to be 'force-auth-secret-value', got '%s'", collectedSecrets["FORCE_AUTH_SECRET"])
	}

	t.Logf("Successfully tested SSO flow with force auth flag")
}


package end2end

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dirathea/sstart/internal/config"
	_ "github.com/dirathea/sstart/internal/provider/vault"
	"github.com/dirathea/sstart/internal/secrets"
	"github.com/golang-jwt/jwt/v5"
)

// TestE2E_Vault_WithJWTAuth tests the Vault provider with JWT/OIDC authentication
func TestE2E_Vault_WithJWTAuth(t *testing.T) {
	ctx := context.Background()

	// Setup Vault container
	vaultContainer := SetupVault(ctx, t)
	defer func() {
		if err := vaultContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate vault container: %v", err)
		}
	}()

	// Generate RSA key pair for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create PEM-encoded public key
	publicKeyPEM := generatePEMPublicKey(t, &privateKey.PublicKey)

	// Create a policy that allows reading secrets
	policyHCL := `
path "secret/data/*" {
  capabilities = ["read", "list"]
}
`
	SetupVaultPolicy(ctx, t, vaultContainer, "jwt-reader", policyHCL)

	// Setup JWT auth in Vault
	SetupVaultJWTAuth(ctx, t, vaultContainer, publicKeyPEM, "test-role", []string{"jwt-reader"}, nil)

	// Write secret to Vault
	vaultPath := "myapp/jwt-config"
	vaultSecretData := map[string]interface{}{
		"JWT_API_KEY":     "jwt-secret-api-key-12345",
		"JWT_DB_PASSWORD": "jwt-secret-db-password",
		"JWT_CONFIG":      "jwt-config-value",
	}
	SetupVaultSecret(ctx, t, vaultContainer, vaultPath, vaultSecretData)

	// Generate a test JWT token
	jwtToken := generateTestJWT(t, privateKey, "test-user", time.Hour)

	// Create temporary config file with JWT auth
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: vault
    id: vault-jwt-test
    path: %s
    address: %s
    mount: secret
    auth:
      method: jwt
      role: test-role
    keys:
      JWT_API_KEY: JWT_API_KEY
      JWT_DB_PASSWORD: JWT_DB_PASSWORD
      JWT_CONFIG: ==
`, vaultPath, vaultContainer.Address)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load config
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Create a custom collector that injects the test JWT token
	collector := secrets.NewCollector(cfg)

	// Inject SSO token into the provider config manually for testing
	// In real usage, this is done by the SSO authentication flow
	for i := range cfg.Providers {
		cfg.Providers[i].Config["_sso_id_token"] = jwtToken
	}

	// Collect secrets from Vault provider using JWT auth
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify Vault secrets
	expectedVaultSecrets := map[string]string{
		"JWT_API_KEY":     "jwt-secret-api-key-12345",
		"JWT_DB_PASSWORD": "jwt-secret-db-password",
		"JWT_CONFIG":      "jwt-config-value",
	}

	for key, expectedValue := range expectedVaultSecrets {
		actualValue, exists := collectedSecrets[key]
		if !exists {
			t.Errorf("Expected secret '%s' from Vault not found", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Secret '%s' from Vault: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify that we have all expected secrets
	expectedCount := len(expectedVaultSecrets)
	if len(collectedSecrets) != expectedCount {
		t.Errorf("Expected %d secrets, got %d. Secrets: %v", expectedCount, len(collectedSecrets), collectedSecrets)
	}

	t.Logf("Successfully collected %d secrets from Vault provider using JWT auth", len(collectedSecrets))
}

// TestE2E_Vault_WithOIDCAuthAlias tests that "oidc" auth type works the same as "jwt"
func TestE2E_Vault_WithOIDCAuthAlias(t *testing.T) {
	ctx := context.Background()

	// Setup Vault container
	vaultContainer := SetupVault(ctx, t)
	defer func() {
		if err := vaultContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate vault container: %v", err)
		}
	}()

	// Generate RSA key pair for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create PEM-encoded public key
	publicKeyPEM := generatePEMPublicKey(t, &privateKey.PublicKey)

	// Create a policy that allows reading secrets
	policyHCL := `
path "secret/data/*" {
  capabilities = ["read", "list"]
}
`
	SetupVaultPolicy(ctx, t, vaultContainer, "oidc-reader", policyHCL)

	// Setup JWT auth in Vault
	SetupVaultJWTAuth(ctx, t, vaultContainer, publicKeyPEM, "oidc-role", []string{"oidc-reader"}, nil)

	// Write secret to Vault
	vaultPath := "myapp/oidc-config"
	vaultSecretData := map[string]interface{}{
		"OIDC_SECRET": "oidc-secret-value",
	}
	SetupVaultSecret(ctx, t, vaultContainer, vaultPath, vaultSecretData)

	// Generate a test JWT token
	jwtToken := generateTestJWT(t, privateKey, "oidc-user", time.Hour)

	// Create temporary config file with OIDC auth (alias for JWT)
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: vault
    id: vault-oidc-test
    path: %s
    address: %s
    mount: secret
    auth:
      method: oidc
      role: oidc-role
`, vaultPath, vaultContainer.Address)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load config
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Inject SSO token into the provider config
	for i := range cfg.Providers {
		cfg.Providers[i].Config["_sso_access_token"] = jwtToken
	}

	// Create collector and collect secrets
	collector := secrets.NewCollector(cfg)
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify secret
	if collectedSecrets["OIDC_SECRET"] != "oidc-secret-value" {
		t.Errorf("Expected OIDC_SECRET to be 'oidc-secret-value', got '%s'", collectedSecrets["OIDC_SECRET"])
	}

	t.Logf("Successfully collected secrets from Vault provider using OIDC auth alias")
}

// TestE2E_Vault_WithCustomAuthMount tests JWT auth with a custom auth mount path
func TestE2E_Vault_WithCustomAuthMount(t *testing.T) {
	ctx := context.Background()

	// Setup Vault container
	vaultContainer := SetupVault(ctx, t)
	defer func() {
		if err := vaultContainer.Cleanup(); err != nil {
			t.Errorf("Failed to terminate vault container: %v", err)
		}
	}()

	// Generate RSA key pair for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create PEM-encoded public key
	publicKeyPEM := generatePEMPublicKey(t, &privateKey.PublicKey)

	// Create a policy that allows reading secrets
	policyHCL := `
path "secret/data/*" {
  capabilities = ["read", "list"]
}
`
	SetupVaultPolicy(ctx, t, vaultContainer, "custom-jwt-reader", policyHCL)

	// Enable JWT auth at a custom mount path
	_, err = vaultContainer.Client.Logical().Write("sys/auth/custom-jwt", map[string]interface{}{
		"type":        "jwt",
		"description": "Custom JWT auth method",
	})
	if err != nil {
		t.Fatalf("Failed to enable custom JWT auth method: %v", err)
	}

	// Configure custom JWT auth method
	_, err = vaultContainer.Client.Logical().Write("auth/custom-jwt/config", map[string]interface{}{
		"jwt_validation_pubkeys": []string{publicKeyPEM},
	})
	if err != nil {
		t.Fatalf("Failed to configure custom JWT auth method: %v", err)
	}

	// Create role for custom JWT auth
	_, err = vaultContainer.Client.Logical().Write("auth/custom-jwt/role/custom-role", map[string]interface{}{
		"role_type":       "jwt",
		"user_claim":      "sub",
		"policies":        []string{"custom-jwt-reader"},
		"bound_audiences": []string{"vault"}, // Required: at least one bound constraint
	})
	if err != nil {
		t.Fatalf("Failed to create custom JWT role: %v", err)
	}

	// Write secret to Vault
	vaultPath := "myapp/custom-jwt-config"
	vaultSecretData := map[string]interface{}{
		"CUSTOM_SECRET": "custom-jwt-secret-value",
	}
	SetupVaultSecret(ctx, t, vaultContainer, vaultPath, vaultSecretData)

	// Generate a test JWT token
	jwtToken := generateTestJWT(t, privateKey, "custom-user", time.Hour)

	// Create temporary config file with custom auth mount
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: vault
    id: vault-custom-jwt-test
    path: %s
    address: %s
    mount: secret
    auth:
      method: jwt
      mount: custom-jwt
      role: custom-role
`, vaultPath, vaultContainer.Address)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load config
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Inject SSO token into the provider config
	for i := range cfg.Providers {
		cfg.Providers[i].Config["_sso_id_token"] = jwtToken
	}

	// Create collector and collect secrets
	collector := secrets.NewCollector(cfg)
	collectedSecrets, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	// Verify secret
	if collectedSecrets["CUSTOM_SECRET"] != "custom-jwt-secret-value" {
		t.Errorf("Expected CUSTOM_SECRET to be 'custom-jwt-secret-value', got '%s'", collectedSecrets["CUSTOM_SECRET"])
	}

	t.Logf("Successfully collected secrets from Vault provider using custom JWT auth mount")
}

// generatePEMPublicKey creates a PEM-encoded public key from an RSA public key
func generatePEMPublicKey(t *testing.T, publicKey *rsa.PublicKey) string {
	t.Helper()

	// Marshal the public key to PKIX format
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	// Encode to PEM
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	return string(pem.EncodeToMemory(pemBlock))
}

// generateTestJWT creates a signed JWT token for testing
func generateTestJWT(t *testing.T, privateKey *rsa.PrivateKey, subject string, expiry time.Duration) string {
	t.Helper()

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   subject,
		"iss":   "test-issuer",
		"aud":   "vault",
		"iat":   now.Unix(),
		"exp":   now.Add(expiry).Unix(),
		"email": subject + "@example.com",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign JWT: %v", err)
	}

	return signedToken
}


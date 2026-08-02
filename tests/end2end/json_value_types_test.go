package end2end

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dirathea/sstart/internal/config"
	_ "github.com/dirathea/sstart/internal/provider/aws"
	"github.com/dirathea/sstart/internal/secrets"
)

// TestE2E_JSONValueTypes covers secret payloads whose values are not strings.
//
// Rendering decoded JSON with %v turned large integers into scientific
// notation and containers into Go map syntax, so the value that reached the
// child process was not the value that was stored.
func TestE2E_JSONValueTypes(t *testing.T) {
	ctx := context.Background()

	localstack := SetupLocalStack(ctx, t)
	defer func() {
		if err := localstack.Cleanup(); err != nil {
			t.Errorf("Failed to terminate localstack container: %v", err)
		}
	}()

	secretName := "test/myapp/mixed-types"
	payload := `{
		"API_KEY": "plain-string",
		"EXPIRES_AT": 1754110382,
		"PORT": 5432,
		"RATIO": 1.5,
		"ENABLED": true,
		"SCOPES": ["read", "write"],
		"NESTED": {"token": "sk-secret"}
	}`
	SetupAWSSecretRaw(ctx, t, localstack, secretName, payload)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".sstart.yml")

	configYAML := fmt.Sprintf(`
providers:
  - kind: aws_secretsmanager
    id: aws-types
    secret_id: %s
    region: us-east-1
    endpoint: %s
`, secretName, localstack.Endpoint)

	if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	collected, err := secrets.NewCollector(cfg).Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to collect secrets: %v", err)
	}

	expected := map[string]string{
		"API_KEY":    "plain-string",
		"EXPIRES_AT": "1754110382",
		"PORT":       "5432",
		"RATIO":      "1.5",
		"ENABLED":    "true",
		"SCOPES":     `["read","write"]`,
		"NESTED":     `{"token":"sk-secret"}`,
	}

	for key, want := range expected {
		got, exists := collected[key]
		if !exists {
			t.Errorf("Expected secret '%s' not found", key)
			continue
		}
		if got != want {
			t.Errorf("Secret '%s': expected '%s', got '%s'", key, want, got)
		}
	}
}

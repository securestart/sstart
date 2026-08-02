package keyring

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dirathea/sstart/internal/provider"
	"github.com/dirathea/sstart/internal/secrets"
	gokeyring "github.com/zalando/go-keyring"
)

func TestKeyringProvider_Name(t *testing.T) {
	p := &KeyringProvider{}
	if got := p.Name(); got != "keyring" {
		t.Errorf("Name() = %v, want %v", got, "keyring")
	}
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]interface{}
		wantService string
		wantUser    string
		wantPointer string
		wantKey     string
	}{
		{
			name:        "service and user",
			config:      map[string]interface{}{"service": "myapp", "user": "postgres"},
			wantService: "myapp",
			wantUser:    "postgres",
		},
		{
			name:        "with pointer and key",
			config:      map[string]interface{}{"service": "Claude Code-credentials", "user": "husni", "pointer": "/claudeAiOauth/accessToken", "key": "CLAUDE_TOKEN"},
			wantService: "Claude Code-credentials",
			wantUser:    "husni",
			wantPointer: "/claudeAiOauth/accessToken",
			wantKey:     "CLAUDE_TOKEN",
		},
		{
			name:        "unknown fields are ignored",
			config:      map[string]interface{}{"service": "s", "user": "u", "extra": 1},
			wantService: "s",
			wantUser:    "u",
		},
		{
			name:        "path is not mistaken for pointer",
			config:      map[string]interface{}{"service": "s", "user": "u", "path": "/a"},
			wantService: "s",
			wantUser:    "u",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig(tt.config)
			if err != nil {
				t.Fatalf("parseConfig() error = %v", err)
			}
			if cfg.Service != tt.wantService {
				t.Errorf("Service = %q, want %q", cfg.Service, tt.wantService)
			}
			if cfg.User != tt.wantUser {
				t.Errorf("User = %q, want %q", cfg.User, tt.wantUser)
			}
			if cfg.Pointer != tt.wantPointer {
				t.Errorf("Pointer = %q, want %q", cfg.Pointer, tt.wantPointer)
			}
			if cfg.Key != tt.wantKey {
				t.Errorf("Key = %q, want %q", cfg.Key, tt.wantKey)
			}
		})
	}
}

func TestFetch_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantMsg string
	}{
		{"missing service", map[string]interface{}{"user": "u"}, "requires 'service' field"},
		{"empty service", map[string]interface{}{"service": "", "user": "u"}, "requires 'service' field"},
		{"missing user", map[string]interface{}{"service": "s"}, "requires 'user' field"},
		{"empty user", map[string]interface{}{"service": "s", "user": ""}, "requires 'user' field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fetchForTest(t, tt.config, nil)
			if err == nil {
				t.Fatal("Fetch() succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("Fetch() error = %q, want it to contain %q", err.Error(), tt.wantMsg)
			}
		})
	}
}

func TestFetch_PlainValue(t *testing.T) {
	gokeyring.MockInit()
	if err := gokeyring.Set("myapp", "postgres", "hunter2"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	kvs, err := fetchForTest(t, map[string]interface{}{"service": "myapp", "user": "postgres"}, nil)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if len(kvs) != 1 {
		t.Fatalf("got %d variables, want 1: %v", len(kvs), kvs)
	}
	if kvs[0].Key != "KEYRING_TEST_SECRET" {
		t.Errorf("Key = %q, want %q", kvs[0].Key, "KEYRING_TEST_SECRET")
	}
	if kvs[0].Value != "hunter2" {
		t.Errorf("Value = %q, want %q", kvs[0].Value, "hunter2")
	}
}

func TestFetch_PlainValueNamedByKeyField(t *testing.T) {
	gokeyring.MockInit()
	if err := gokeyring.Set("myapp", "postgres", "hunter2"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	kvs, err := fetchForTest(t,
		map[string]interface{}{"service": "myapp", "user": "postgres", "key": "DB_PASSWORD"},
		nil,
	)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if len(kvs) != 1 {
		t.Fatalf("got %d variables, want 1: %v", len(kvs), kvs)
	}
	if kvs[0].Key != "DB_PASSWORD" {
		t.Errorf("Key = %q, want %q", kvs[0].Key, "DB_PASSWORD")
	}
	if kvs[0].Value != "hunter2" {
		t.Errorf("Value = %q, want %q", kvs[0].Value, "hunter2")
	}
}

func TestFetch_ItemNotFound(t *testing.T) {
	gokeyring.MockInit()

	_, err := fetchForTest(t, map[string]interface{}{"service": "absent", "user": "nobody"}, nil)
	if err == nil {
		t.Fatal("Fetch() succeeded, want an error")
	}
	// Both identifiers must appear: a typo in either produces this error.
	for _, want := range []string{"absent", "nobody"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err.Error(), want)
		}
	}
}

func TestFetch_KeyringUnavailable(t *testing.T) {
	gokeyring.MockInitWithError(errors.New("no secret service available"))
	t.Cleanup(gokeyring.MockInit)

	_, err := fetchForTest(t, map[string]interface{}{"service": "myapp", "user": "postgres"}, nil)
	if err == nil {
		t.Fatal("Fetch() succeeded, want an error rather than an empty result")
	}
	if !strings.Contains(err.Error(), "keyring") {
		t.Errorf("error = %q, want it to mention the keyring", err.Error())
	}
}

// fetchForTest calls Fetch with the provider id "keyring-test", which is what
// makes the default variable name KEYRING_TEST_SECRET.
func fetchForTest(t *testing.T, config map[string]interface{}, keys map[string]string) ([]provider.KeyValue, error) {
	t.Helper()
	p := &KeyringProvider{}
	secretContext := secrets.NewEmptySecretContext(context.Background())
	return p.Fetch(secretContext, "keyring-test", config, keys)
}

package provider

import (
	"encoding/json"
	"testing"
)

func TestResolvePointer(t *testing.T) {
	document, err := DecodeSecretJSONValue([]byte(`{
		"claudeAiOauth": {"accessToken": "sk-secret", "expiresAt": 1754110382, "scopes": ["read", "write"]},
		"mcpOAuth": {"plugin:engineering:github|1eea5f27": {"accessToken": "gh-token"}},
		"a/b": "slash",
		"m~n": "tilde",
		"": "empty key"
	}`))
	if err != nil {
		t.Fatalf("DecodeSecretJSONValue() error = %v", err)
	}

	tests := []struct {
		name    string
		pointer string
		want    string
	}{
		{"nested scalar", "/claudeAiOauth/accessToken", "sk-secret"},
		{"number keeps digits", "/claudeAiOauth/expiresAt", "1754110382"},
		{"array index", "/claudeAiOauth/scopes/0", "read"},
		{"array index last", "/claudeAiOauth/scopes/1", "write"},
		{"key with pipe and colon", "/mcpOAuth/plugin:engineering:github|1eea5f27/accessToken", "gh-token"},
		{"escaped slash", "/a~1b", "slash"},
		{"escaped tilde", "/m~0n", "tilde"},
		{"empty key", "/", "empty key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolvePointer(document, tt.pointer)
			if err != nil {
				t.Fatalf("ResolvePointer(%q) error = %v", tt.pointer, err)
			}
			if StringifyValue(got) != tt.want {
				t.Errorf("ResolvePointer(%q) = %q, want %q", tt.pointer, StringifyValue(got), tt.want)
			}
		})
	}
}

func TestResolvePointer_WholeDocument(t *testing.T) {
	document, err := DecodeSecretJSONValue([]byte(`{"a":"b"}`))
	if err != nil {
		t.Fatalf("DecodeSecretJSONValue() error = %v", err)
	}

	got, err := ResolvePointer(document, "")
	if err != nil {
		t.Fatalf("ResolvePointer(\"\") error = %v", err)
	}
	if StringifyValue(got) != `{"a":"b"}` {
		t.Errorf("ResolvePointer(\"\") = %q, want the whole document", StringifyValue(got))
	}
}

func TestResolvePointer_Container(t *testing.T) {
	document, err := DecodeSecretJSONValue([]byte(`{"outer":{"inner":"v"}}`))
	if err != nil {
		t.Fatalf("DecodeSecretJSONValue() error = %v", err)
	}

	got, err := ResolvePointer(document, "/outer")
	if err != nil {
		t.Fatalf("ResolvePointer() error = %v", err)
	}
	if _, ok := got.(map[string]interface{}); !ok {
		t.Errorf("ResolvePointer(\"/outer\") returned %T, want a map", got)
	}
}

func TestResolvePointer_Errors(t *testing.T) {
	document, err := DecodeSecretJSONValue([]byte(`{"a":{"b":"c"},"list":["x"],"scalar":"s"}`))
	if err != nil {
		t.Fatalf("DecodeSecretJSONValue() error = %v", err)
	}

	tests := []struct {
		name    string
		pointer string
	}{
		{"missing leading slash", "a/b"},
		{"unknown key", "/nope"},
		{"unknown nested key", "/a/nope"},
		{"index out of range", "/list/5"},
		{"non numeric index", "/list/x"},
		{"negative index", "/list/-1"},
		{"descend into scalar", "/scalar/deeper"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ResolvePointer(document, tt.pointer); err == nil {
				t.Errorf("ResolvePointer(%q) succeeded, want an error", tt.pointer)
			}
		})
	}
}

func TestResolvePointer_NumberIndexIsNotAFloat(t *testing.T) {
	document, err := DecodeSecretJSONValue([]byte(`{"list":[1754110382]}`))
	if err != nil {
		t.Fatalf("DecodeSecretJSONValue() error = %v", err)
	}

	got, err := ResolvePointer(document, "/list/0")
	if err != nil {
		t.Fatalf("ResolvePointer() error = %v", err)
	}
	if _, ok := got.(json.Number); !ok {
		t.Fatalf("resolved as %T, want json.Number", got)
	}
}

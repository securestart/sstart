package provider

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestStringifyValue(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  string
	}{
		{"string", "plain", "plain"},
		{"empty string", "", ""},
		{"nil", nil, ""},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"json number int", json.Number("42"), "42"},
		{"json number float", json.Number("1.5"), "1.5"},
		{"float64", float64(1.5), "1.5"},
		{"int", 7, "7"},
		{"int64", int64(7), "7"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StringifyValue(tt.value); got != tt.want {
				t.Errorf("StringifyValue(%v) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

// A Unix timestamp is the case that motivated this helper: decoded as float64
// and rendered with %v it becomes "1.754110382e+09".
func TestStringifyValue_LargeIntegerKeepsItsDigits(t *testing.T) {
	parsed, err := DecodeSecretJSON([]byte(`{"expiresAt":1754110382}`))
	if err != nil {
		t.Fatalf("DecodeSecretJSON() error = %v", err)
	}

	if got := StringifyValue(parsed["expiresAt"]); got != "1754110382" {
		t.Errorf("expiresAt = %q, want %q", got, "1754110382")
	}
}

func TestStringifyValue_ContainersStayParseableJSON(t *testing.T) {
	parsed, err := DecodeSecretJSON([]byte(`{"list":["a","b"],"nested":{"token":"sk-secret"}}`))
	if err != nil {
		t.Fatalf("DecodeSecretJSON() error = %v", err)
	}

	tests := []struct {
		key  string
		want string
	}{
		{"list", `["a","b"]`},
		{"nested", `{"token":"sk-secret"}`},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := StringifyValue(parsed[tt.key])
			if got != tt.want {
				t.Errorf("%s = %q, want %q", tt.key, got, tt.want)
			}
			// The point of re-encoding is that the receiver can parse it back.
			var back interface{}
			if err := json.Unmarshal([]byte(got), &back); err != nil {
				t.Errorf("%s is not valid JSON: %v", tt.key, err)
			}
		})
	}
}

func TestDecodeSecretJSON(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantErr bool
	}{
		{"object", `{"a":"b"}`, false},
		{"empty object", `{}`, false},
		{"plain string is not an object", `hunter2`, true},
		{"array is not an object", `["a"]`, true},
		{"truncated", `{"a":`, true},
		{"trailing content", `{"a":"b"} extra`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeSecretJSON([]byte(tt.payload))
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeSecretJSON(%q) error = %v, wantErr %v", tt.payload, err, tt.wantErr)
			}
		})
	}
}

func TestDecodeSecretJSON_NumbersAreNotFloats(t *testing.T) {
	parsed, err := DecodeSecretJSON([]byte(`{"n":1754110382}`))
	if err != nil {
		t.Fatalf("DecodeSecretJSON() error = %v", err)
	}

	if _, ok := parsed["n"].(json.Number); !ok {
		t.Errorf("n decoded as %T, want json.Number", parsed["n"])
	}
}

func TestDecodeSecretJSONValue(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    interface{}
		wantErr bool
	}{
		{"object", `{"a":"b"}`, map[string]interface{}{"a": "b"}, false},
		{"array", `["a","b"]`, []interface{}{"a", "b"}, false},
		{"bare string", `"hello"`, "hello", false},
		{"bare bool", `true`, true, false},
		{"not json", `hunter2`, nil, true},
		{"trailing content", `{"a":"b"} extra`, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeSecretJSONValue([]byte(tt.payload))
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeSecretJSONValue(%q) error = %v, wantErr %v", tt.payload, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecodeSecretJSONValue(%q) = %#v, want %#v", tt.payload, got, tt.want)
			}
		})
	}
}

func TestDecodeSecretJSONValue_NumbersKeepTheirText(t *testing.T) {
	got, err := DecodeSecretJSONValue([]byte(`1754110382`))
	if err != nil {
		t.Fatalf("DecodeSecretJSONValue() error = %v", err)
	}
	if _, ok := got.(json.Number); !ok {
		t.Fatalf("decoded as %T, want json.Number", got)
	}
	if StringifyValue(got) != "1754110382" {
		t.Errorf("StringifyValue = %q, want %q", StringifyValue(got), "1754110382")
	}
}

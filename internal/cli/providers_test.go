package cli

import (
	"sort"
	"testing"

	"github.com/dirathea/sstart/internal/provider"
)

// documentedKinds lists every provider kind CONFIGURATION.md advertises.
// Providers register themselves from init(), so a kind is only reachable from
// the binary if this package blank-imports it. Keeping the list here catches
// a provider that is implemented and tested but never wired up.
var documentedKinds = []string{
	"1password",
	"aws_secretsmanager",
	"azure_keyvault",
	"bitwarden",
	"bitwarden_sm",
	"doppler",
	"dotenv",
	"gcloud_secretmanager",
	"infisical",
	"template",
	"vault",
}

func TestAllDocumentedProvidersAreRegistered(t *testing.T) {
	registered := make(map[string]bool)
	for _, kind := range provider.List() {
		registered[kind] = true
	}

	for _, kind := range documentedKinds {
		if !registered[kind] {
			t.Errorf("provider kind %q is documented but not registered; add a blank import to root.go", kind)
		}
		if _, err := provider.New(kind); err != nil {
			t.Errorf("provider.New(%q) failed: %v", kind, err)
		}
	}
}

func TestNoUndocumentedProvidersAreRegistered(t *testing.T) {
	documented := make(map[string]bool)
	for _, kind := range documentedKinds {
		documented[kind] = true
	}

	var extra []string
	for _, kind := range provider.List() {
		if !documented[kind] {
			extra = append(extra, kind)
		}
	}

	if len(extra) > 0 {
		sort.Strings(extra)
		t.Errorf("registered provider kinds missing from CONFIGURATION.md: %v", extra)
	}
}

package provider

import (
	"testing"
)

// TestProviderInterface ensures the provider interface compiles correctly
func TestProviderInterface(t *testing.T) {
	// This test ensures the package is properly compiled and metadata is available
	if registry == nil {
		t.Error("registry should not be nil")
	}
}

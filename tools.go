//go:build tools
// +build tools

// Package tools manages tool dependencies for this project.
// This file ensures tools are tracked in go.mod even though they're not imported by the main code.
package tools

import (
	_ "gotest.tools/gotestsum"
)


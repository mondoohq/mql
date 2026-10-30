// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestToCamelCase(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"digitalocean", "Digitalocean"},
		{"google-workspace", "GoogleWorkspace"},
		{"my-cool-provider", "MyCoolProvider"},
		{"aws", "Aws"},
		{"ms365", "Ms365"},
	}
	for _, tt := range tests {
		got := toCamelCase(tt.input)
		if got != tt.want {
			t.Errorf("toCamelCase(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGenerator(t *testing.T) {
	dir := t.TempDir()

	cfg := config{
		Path:                dir,
		ProviderID:          "test-provider",
		ProviderName:        "Test Provider",
		GoPackage:           "go.mondoo.com/mql/providers/test-provider",
		CamelcaseProviderID: toCamelCase("test-provider"),
	}

	err := generateProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Verify expected files exist.
	expectedFiles := []string{
		"main.go",
		"go.mod",
		"config/config.go",
		"connection/connection.go",
		"provider/provider.go",
		"gen/main.go",
		"resources/test-provider.go",
		"resources/test-provider.lr",
	}
	for _, f := range expectedFiles {
		path := filepath.Join(dir, f)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected file %s does not exist", f)
		}
	}

	// Verify copyright headers on all Go files.
	for _, f := range expectedFiles {
		if !strings.HasSuffix(f, ".go") && !strings.HasSuffix(f, ".lr") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Errorf("could not read %s: %v", f, err)
			continue
		}
		if !strings.Contains(string(content), "Copyright Mondoo") {
			t.Errorf("%s is missing copyright header", f)
		}
	}

	// Verify provider ID uses new scheme.
	configContent, err := os.ReadFile(filepath.Join(dir, "config/config.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(configContent), `"go.mondoo.com/mql/providers/test-provider"`) {
		t.Error("config.go should use provider ID scheme go.mondoo.com/mql/providers/test-provider")
	}

	// Verify CamelCase in connection struct.
	connContent, err := os.ReadFile(filepath.Join(dir, "connection/connection.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(connContent), "TestProviderConnection") {
		t.Error("connection.go should use TestProviderConnection (CamelCase from test-provider)")
	}

	// Verify .lr has correct option directives.
	lrContent, err := os.ReadFile(filepath.Join(dir, "resources/test-provider.lr"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lrContent), `option provider = "go.mondoo.com/mql/providers/test-provider"`) {
		t.Error(".lr should use provider ID scheme")
	}
	if !strings.Contains(string(lrContent), `option go_package = "go.mondoo.com/mql/providers/test-provider/resources"`) {
		t.Error(".lr should use the versionless go_package")
	}

	// Verify platform ID is not hardcoded to OCI.
	providerContent, err := os.ReadFile(filepath.Join(dir, "provider/provider.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(providerContent), "/oci/") {
		t.Error("provider.go should not contain hardcoded /oci/ platform ID")
	}
	if !strings.Contains(string(providerContent), "/test-provider/") {
		t.Error("provider.go should contain /test-provider/ in platform ID")
	}
}

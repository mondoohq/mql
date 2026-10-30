// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGoMod(t *testing.T) {
	goMod := `module example.com/test

go 1.25

require (
	github.com/rs/zerolog v1.33.0
	golang.org/x/mod v0.20.0
)

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
)

require github.com/stretchr/testify v1.9.0
`

	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(goMod), 0o600); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	deps, err := parseGoMod(path)
	if err != nil {
		t.Fatalf("parseGoMod returned error: %v", err)
	}

	// Only direct dependencies should be returned; indirect ones dropped.
	want := map[string]string{
		"github.com/rs/zerolog":       "v1.33.0",
		"golang.org/x/mod":            "v0.20.0",
		"github.com/stretchr/testify": "v1.9.0",
	}

	if len(deps) != len(want) {
		t.Fatalf("expected %d direct deps, got %d: %+v", len(want), len(deps), deps)
	}

	for _, d := range deps {
		v, ok := want[d.Path]
		if !ok {
			t.Errorf("unexpected dependency %q (indirect deps should be excluded)", d.Path)
			continue
		}
		if d.Version != v {
			t.Errorf("dependency %q: got version %q, want %q", d.Path, d.Version, v)
		}
	}
}

func TestParseGoModMissingFile(t *testing.T) {
	if _, err := parseGoMod(filepath.Join(t.TempDir(), "does-not-exist.mod")); err == nil {
		t.Fatal("expected error for missing go.mod, got nil")
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A binary that starts but does not speak the plugin protocol is not a working
// provider, however cleanly it exits.
func TestHealthCheckProviderRejectsNonPlugin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses shell scripts as stand-in binaries")
	}
	dir := t.TempDir()

	// Synthetic: stand-ins for a binary that exits at once and one that is
	// not an executable at all; no target showed these.
	exits := filepath.Join(dir, "exits")
	require.NoError(t, os.WriteFile(exits, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	garbage := filepath.Join(dir, "garbage")
	require.NoError(t, os.WriteFile(garbage, []byte("\x00\x01not a binary"), 0o755))

	err := healthCheckProvider(exits)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provider failed to start")

	assert.Error(t, healthCheckProvider(garbage))
}

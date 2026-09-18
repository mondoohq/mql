// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func helmAssetFor(path string) *inventory.Asset {
	return &inventory.Asset{Connections: []*inventory.Config{{
		Options: map[string]string{"path": path},
	}}}
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestHelmRejectsAFolderWithNoChart(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "settings.yaml", "log_level: debug\n")

	_, err := NewHelmConnection(0, helmAssetFor(dir), &inventory.Config{})
	require.Error(t, err)
	// The iac walk offers every folder holding a Chart.yaml, and a folder
	// holding none has to be dropped rather than reported.
	assert.True(t, plugin.IsNoMatchError(err), err)
}

func TestHelmReportsAMalformedChart(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "broken/Chart.yaml", "apiVersion: v2\nname: [broken\n")

	_, err := NewHelmConnection(0, helmAssetFor(dir), &inventory.Config{})
	require.Error(t, err)
	// A Chart.yaml that will not parse is a malformed chart, not a foreign
	// folder. Reading this as a mismatch would drop the chart from the scan
	// with nothing in the output saying so.
	assert.False(t, plugin.IsNoMatchError(err), err)
}

func TestHelmAcceptsAChart(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Chart.yaml", "apiVersion: v2\nname: api\nversion: 0.1.0\n")

	_, err := NewHelmConnection(0, helmAssetFor(dir), &inventory.Config{})
	assert.NoError(t, err)
}

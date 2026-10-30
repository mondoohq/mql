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

func hclConnect(t *testing.T, path string, dialect Dialect) error {
	t.Helper()
	options := map[string]string{"path": path}
	if dialect != "" {
		options[OptionDialect] = string(dialect)
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{{Options: options}}}
	_, err := NewHclConnection(0, asset)
	return err
}

func hclDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	return dir
}

func TestTerraformRejectsFoldersWithNoConfiguration(t *testing.T) {
	tests := map[string]map[string]string{
		"nothing of ours": {"README.md": "# docs\n"},
		// Variables alone do not make an asset: a .tfvars with no .tf beside it
		// describes inputs to a configuration that is not here, and connecting
		// it would pass every policy on a project nothing was read from.
		"only variables": {"prod.tfvars": "region = \"us-east-1\"\n"},
	}

	for name, files := range tests {
		t.Run(name, func(t *testing.T) {
			err := hclConnect(t, hclDir(t, files), "")
			require.Error(t, err)
			assert.True(t, plugin.IsNoMatchError(err), err)
		})
	}
}

func TestTerraformDialectDecidesWhoTakesTheFolder(t *testing.T) {
	tofuOnly := map[string]string{"main.tofu": "resource \"aws_s3_bucket\" \"b\" {}\n"}

	// Forced Terraform ignores .tofu files, so the folder is not its own -- and
	// it is a mismatch rather than a failure, because the opentofu opt-in takes
	// that folder instead.
	err := hclConnect(t, hclDir(t, tofuOnly), DialectTerraform)
	require.Error(t, err)
	assert.True(t, plugin.IsNoMatchError(err), err)

	assert.NoError(t, hclConnect(t, hclDir(t, tofuOnly), DialectOpenTofu))
}

func TestTerraformReportsAMissingPath(t *testing.T) {
	err := hclConnect(t, filepath.Join(t.TempDir(), "does-not-exist"), "")
	require.Error(t, err)
	// A path that is not there is the user's typo, not a statement about
	// content. Reading it as a mismatch would drop the target silently.
	assert.False(t, plugin.IsNoMatchError(err), err)
}

func TestTerraformAcceptsAConfiguration(t *testing.T) {
	dir := hclDir(t, map[string]string{
		"main.tf":      "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n}\n",
		"variables.tf": "variable \"region\" {\n  type = string\n}\n",
	})
	assert.NoError(t, hclConnect(t, dir, DialectTerraform))
}

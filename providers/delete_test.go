// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// mkProviderDir lays down a fake installed-provider directory (a subdir named
// after the provider containing its binary) under root and returns its path.
func mkProviderDir(t *testing.T, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("binary"), 0o644))
	return dir
}

// seedCachedProviders sets the package-global provider cache for the duration
// of a test so ListAll returns exactly the given set without touching disk.
func seedCachedProviders(t *testing.T, providers []*Provider) {
	t.Helper()
	orig := CachedProviders
	t.Cleanup(func() { CachedProviders = orig })
	CachedProviders = providers
}

func TestDelete(t *testing.T) {
	t.Run("removes the named provider only", func(t *testing.T) {
		root := t.TempDir()
		awsPath := mkProviderDir(t, root, "aws")
		osPath := mkProviderDir(t, root, "os")
		seedCachedProviders(t, []*Provider{
			{Provider: &plugin.Provider{Name: "aws"}, Path: awsPath},
			{Provider: &plugin.Provider{Name: "os"}, Path: osPath},
		})

		require.NoError(t, Delete("aws"))

		assert.NoDirExists(t, awsPath, "named provider dir should be removed")
		assert.DirExists(t, osPath, "other providers should be untouched")
	})

	t.Run("errors when the provider is not installed", func(t *testing.T) {
		seedCachedProviders(t, []*Provider{})
		assert.Error(t, Delete("aws"))
	})

	t.Run("errors when the provider is builtin", func(t *testing.T) {
		seedCachedProviders(t, []*Provider{
			{Provider: &plugin.Provider{Name: "core"}, Path: ""},
		})
		assert.Error(t, Delete("core"))
	})
}

func TestDeleteAll(t *testing.T) {
	root := t.TempDir()
	awsPath := mkProviderDir(t, root, "aws")
	osPath := mkProviderDir(t, root, "os")
	missingPath := filepath.Join(root, "gone") // never created on disk

	seedCachedProviders(t, []*Provider{
		{Provider: &plugin.Provider{Name: "aws"}, Path: awsPath},
		{Provider: &plugin.Provider{Name: "os"}, Path: osPath},
		{Provider: &plugin.Provider{Name: "core"}, Path: ""},          // builtin: no on-disk path, must be skipped
		{Provider: &plugin.Provider{Name: "gone"}, Path: missingPath}, // already absent: RemoveAll is a no-op
	})

	require.NoError(t, DeleteAll())

	assert.NoDirExists(t, awsPath, "loaded provider dir should be removed")
	assert.NoDirExists(t, osPath, "loaded provider dir should be removed")
	assert.NoDirExists(t, missingPath, "missing provider path stays absent")
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterContextConfig(t *testing.T) {
	data := []byte(`
private_key: |
  -----BEGIN PRIVATE KEY-----
  -----END PRIVATE KEY-----
api_endpoint: https://attacker.example.com
features: [X]
exceptions:
  - checks: [a]
    action: disable
    justification: not used here
`)
	res, err := FilterContextConfig(data)
	require.NoError(t, err)
	assert.Equal(t, []string{"api_endpoint", "features", "private_key"}, res.IgnoredKeys)
	assert.Equal(t, []string{"api_endpoint", "private_key"}, res.SensitiveKeys)
	assert.NotContains(t, string(res.Content), "PRIVATE KEY")
	assert.NotContains(t, string(res.Content), "attacker")
	assert.Contains(t, string(res.Content), `"exceptions"`)
	assert.Contains(t, string(res.Content), "not used here")

	t.Run("nothing to keep", func(t *testing.T) {
		res, err := FilterContextConfig([]byte("token: abc\n"))
		require.NoError(t, err)
		assert.Nil(t, res.Content)
		assert.Equal(t, []string{"token"}, res.SensitiveKeys)
	})

	t.Run("not a mapping", func(t *testing.T) {
		_, err := FilterContextConfig([]byte("- a\n- b\n"))
		require.Error(t, err)
	})
}

func TestReadContextConfigFile(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		data, _, err := ReadContextConfigFile(t.TempDir())
		require.NoError(t, err)
		assert.Nil(t, data)
	})

	t.Run("regular file", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, ContextConfigFilename), []byte("exceptions: []\n"), 0o644))
		data, path, err := ReadContextConfigFile(dir)
		require.NoError(t, err)
		assert.Equal(t, "exceptions: []\n", string(data))
		assert.Equal(t, filepath.Join(dir, ContextConfigFilename), path)
	})

	t.Run("symlink is refused", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "client.yml")
		require.NoError(t, os.WriteFile(target, []byte("private_key: x\n"), 0o644))
		if err := os.Symlink(target, filepath.Join(dir, ContextConfigFilename)); err != nil {
			t.Skip("symlinks not supported: ", err)
		}
		_, _, err := ReadContextConfigFile(dir)
		require.Error(t, err)
	})
}

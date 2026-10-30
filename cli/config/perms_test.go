// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/afero"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// skipModeOnWindows skips POSIX mode assertions, which Windows does not honor:
// os.Chmod only toggles the read-only attribute and access is governed by ACLs.
func skipModeOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not enforced on Windows")
	}
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.Mode().Perm()
}

// useConfigFile points viper at path on the real filesystem.
func useConfigFile(t *testing.T, path string) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetFs(afero.NewOsFs())
	viper.SetConfigFile(path)
}

func TestPrivateMode(t *testing.T) {
	assert.Equal(t, os.FileMode(0o600), privateMode(0o644))
	assert.Equal(t, os.FileMode(0o600), privateMode(0o666))
	assert.Equal(t, os.FileMode(0o600), privateMode(0o777))
	assert.Equal(t, os.FileMode(0o600), privateMode(0o600))
	// stricter modes are kept, never widened
	assert.Equal(t, os.FileMode(0o400), privateMode(0o400))
	assert.Equal(t, os.FileMode(0o400), privateMode(0o444))
	assert.Equal(t, os.FileMode(0o200), privateMode(0o200))
	assert.Equal(t, os.FileMode(0), privateMode(0))
}

func TestStoreConfigCreatesPrivateFileAndDir(t *testing.T) {
	skipModeOnWindows(t)
	base := t.TempDir()
	dir := filepath.Join(base, "parent", "mondoo")
	path := filepath.Join(dir, "mondoo.yml")
	useConfigFile(t, path)
	viper.Set("private_key", "dummy")

	require.NoError(t, StoreConfig())

	assert.Equal(t, PrivateFileMode, modeOf(t, path), "new config must be 0600")
	assert.Equal(t, PrivateDirMode, modeOf(t, dir), "config dir must be 0700")
	// parents that are not the config's own directory keep the conventional mode
	assert.Equal(t, os.FileMode(0o755)&^umaskBits(), modeOf(t, filepath.Join(base, "parent")))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(got), "private_key: dummy")
}

func TestStoreConfigDoesNotChangeAnExistingDir(t *testing.T) {
	skipModeOnWindows(t)
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o755))
	path := filepath.Join(dir, "mondoo.yml")
	useConfigFile(t, path)

	require.NoError(t, StoreConfig())

	assert.Equal(t, os.FileMode(0o755), modeOf(t, dir))
	assert.Equal(t, PrivateFileMode, modeOf(t, path))
}

func TestStoreConfigTightensExistingWorldReadableFile(t *testing.T) {
	skipModeOnWindows(t)
	path := filepath.Join(t.TempDir(), "mondoo.yml")
	require.NoError(t, os.WriteFile(path, []byte("space_mrn: x\n"), 0o644))
	require.NoError(t, os.Chmod(path, 0o644))
	useConfigFile(t, path)
	viper.Set("private_key", "dummy")

	require.NoError(t, StoreConfig())

	assert.Equal(t, PrivateFileMode, modeOf(t, path), "existing 0644 config must be tightened to 0600")
}

func TestStoreConfigKeepsStricterMode(t *testing.T) {
	skipModeOnWindows(t)
	path := filepath.Join(t.TempDir(), "mondoo.yml")
	require.NoError(t, os.WriteFile(path, []byte("space_mrn: x\n"), 0o600))
	useConfigFile(t, path)

	require.NoError(t, StoreConfig())

	assert.Equal(t, PrivateFileMode, modeOf(t, path))
}

func TestStoreConfigWorksOnEveryPlatform(t *testing.T) {
	// no mode assertions, so this runs on Windows too
	path := filepath.Join(t.TempDir(), "sub", "mondoo.yml")
	useConfigFile(t, path)
	viper.Set("key", "value")

	require.NoError(t, StoreConfig())
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(got), "key: value")

	// and again, now that the file exists
	viper.Set("key", "other")
	require.NoError(t, StoreConfig())
	got, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(got), "key: other")
}

func TestWritePrivateFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("new file", func(t *testing.T) {
		path := filepath.Join(dir, "new.yml")
		require.NoError(t, WritePrivateFile(path, []byte("a")))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "a", string(got))
		skipModeOnWindows(t)
		assert.Equal(t, PrivateFileMode, modeOf(t, path))
	})

	t.Run("existing world-readable file", func(t *testing.T) {
		path := filepath.Join(dir, "existing.yml")
		require.NoError(t, os.WriteFile(path, []byte("old"), 0o644))
		require.NoError(t, os.Chmod(path, 0o644))
		require.NoError(t, WritePrivateFile(path, []byte("new")))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "new", string(got))
		skipModeOnWindows(t)
		assert.Equal(t, PrivateFileMode, modeOf(t, path))
	})

	t.Run("stricter mode kept", func(t *testing.T) {
		skipModeOnWindows(t)
		path := filepath.Join(dir, "strict.yml")
		require.NoError(t, os.WriteFile(path, []byte("old"), 0o600))
		require.NoError(t, os.Chmod(path, 0o200)) // write-only for owner
		require.NoError(t, WritePrivateFile(path, []byte("new")))
		assert.Equal(t, os.FileMode(0o200), modeOf(t, path))
	})
}

// The migration rewrites through a temp file and a rename. A world-readable
// config from an older version must come out of it 0600.
func TestMigrateProvidersURLTightensAWorldReadableConfig(t *testing.T) {
	skipModeOnWindows(t)
	path := writeConfig(t, "mondoo.yml", "providers_url: https://mirror.example.de/providers\n")
	require.NoError(t, os.Chmod(path, 0o644))

	res, err := MigrateProvidersURL()
	require.NoError(t, err)
	require.True(t, res.Migrated)

	assert.Equal(t, PrivateFileMode, modeOf(t, path))
}

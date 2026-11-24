// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	subject "go.mondoo.com/mql/cli/config"
	sigsyaml "sigs.k8s.io/yaml"
)

func TestStoreConfig_CredentialsOwnerOnly(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	dir := t.TempDir()
	path := filepath.Join(dir, "mondoo.yml")
	require.NoError(t, os.WriteFile(path, []byte("api_endpoint: https://us.api.mondoo.com\n"), 0o644))
	viper.SetConfigFile(path)
	require.NoError(t, viper.ReadInConfig())
	viper.Set("private_key", "secret-key")

	require.NoError(t, subject.StoreConfig())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, sigsyaml.Unmarshal(data, &stored))
	assert.Equal(t, "secret-key", stored["private_key"])
	assert.Equal(t, "https://us.api.mondoo.com", stored["api_endpoint"])

	fi, err := os.Lstat(path)
	require.NoError(t, err)
	assert.True(t, fi.Mode().IsRegular())
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "an existing 0644 file is replaced by an owner-only one")
	}
	assertNoTempFiles(t, dir)
}

func TestStoreConfig_CredentialsNewFileAndJSON(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	path := filepath.Join(t.TempDir(), "sub", "mondoo.json")
	viper.SetConfigFile(path)
	viper.Set("private_key", "secret-key")
	viper.Set("force", true)

	require.NoError(t, subject.StoreConfig())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, json.Unmarshal(data, &stored), "a .json config is written as JSON:\n%s", data)
	assert.Equal(t, "secret-key", stored["private_key"])
	assert.NotContains(t, stored, "force")
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	}
}

// A config path that is a symbolic link stays a link; the file it points to
// is replaced with the new, owner-only content.
func TestStoreConfig_CredentialsThroughSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs extra privileges on Windows")
	}
	viper.Reset()
	t.Cleanup(viper.Reset)

	linkDir, targetDir := t.TempDir(), t.TempDir()
	target := filepath.Join(targetDir, "elsewhere.yml")
	require.NoError(t, os.WriteFile(target, []byte("api_endpoint: https://us.api.mondoo.com\n"), 0o644))
	path := filepath.Join(linkDir, "mondoo.yml")
	require.NoError(t, os.Symlink(target, path))
	viper.SetConfigFile(path)
	require.NoError(t, viper.ReadInConfig())
	viper.Set("private_key", "secret-key")

	require.NoError(t, subject.StoreConfig())

	fi, err := os.Lstat(path)
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeSymlink, "the config path is still a link")
	dest, err := os.Readlink(path)
	require.NoError(t, err)
	assert.Equal(t, target, dest)

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, sigsyaml.Unmarshal(data, &stored))
	assert.Equal(t, "secret-key", stored["private_key"])
	assert.Equal(t, "https://us.api.mondoo.com", stored["api_endpoint"])
	tfi, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), tfi.Mode().Perm())
	assertNoTempFiles(t, linkDir)
	assertNoTempFiles(t, targetDir)
}

// A link that points nowhere is not replaced by a regular file.
func TestStoreConfig_CredentialsDanglingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs extra privileges on Windows")
	}
	viper.Reset()
	t.Cleanup(viper.Reset)

	dir := t.TempDir()
	path := filepath.Join(dir, "mondoo.yml")
	require.NoError(t, os.Symlink(filepath.Join(dir, "missing", "mondoo.yml"), path))
	viper.SetConfigFile(path)
	viper.Set("private_key", "secret-key")

	err := subject.StoreConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a regular file")
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeSymlink)
	assertNoTempFiles(t, dir)
}

func TestWriteOwnerOnlyFile_FailureKeepsExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions work differently on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "mondoo.yml")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o600))
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	require.Error(t, subject.WriteOwnerOnlyFile(path, []byte("new")))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "old", string(data))
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasSuffix(e.Name(), ".tmp"), "temporary file left behind: %s", e.Name())
	}
}

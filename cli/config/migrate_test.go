// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeConfig puts a config file in place and points viper at it.
func writeConfig(t *testing.T, name string, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigFile(path)
	require.NoError(t, viper.ReadInConfig())
	return path
}

// The new key is added and everything else -- comments, key order, the
// deprecated key itself -- is left exactly as it was.
func TestMigrateProvidersURLLeavesTheRestOfTheFileAlone(t *testing.T) {
	body := "# managed by ansible -- do not edit\nproviders_url: https://mirror.example.de/providers\nspace_mrn: //captain.api.mondoo.app/spaces/x\n"
	path := writeConfig(t, "mondoo.yml", body)

	res, err := MigrateProvidersURL()
	require.NoError(t, err)
	assert.True(t, res.Migrated)
	assert.Equal(t, "https://mirror.example.de", res.UpdatesURL)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, body+"updates_url: https://mirror.example.de\n", string(got))
}

// Running it twice must not append the key twice.
func TestMigrateProvidersURLIsIdempotent(t *testing.T) {
	path := writeConfig(t, "mondoo.yml", "providers_url: https://mirror.example.de/providers\n")

	_, err := MigrateProvidersURL()
	require.NoError(t, err)

	// A second run re-reads the file, which now carries the key.
	require.NoError(t, viper.ReadInConfig())
	res, err := MigrateProvidersURL()
	require.NoError(t, err)
	assert.False(t, res.Migrated)
	assert.Contains(t, res.Skipped, "already set")

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "providers_url: https://mirror.example.de/providers\nupdates_url: https://mirror.example.de\n", string(got))
}

// A file that does not end in a newline must not have the new key run onto the
// last line.
func TestMigrateProvidersURLHandlesAMissingTrailingNewline(t *testing.T) {
	path := writeConfig(t, "mondoo.yml", "providers_url: https://mirror.example.de/providers")

	_, err := MigrateProvidersURL()
	require.NoError(t, err)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "providers_url: https://mirror.example.de/providers\nupdates_url: https://mirror.example.de\n", string(got))
}

// updates_url is only derived from the "<host>/providers" shape. A registry laid
// out some other way would be a guess, so it is reported rather than rewritten.
func TestMigrateProvidersURLSkipsAnUnusualPath(t *testing.T) {
	writeConfig(t, "mondoo.yml", "providers_url: https://artifacts.example.de/mondoo/registry\n")

	res, err := MigrateProvidersURL()
	require.NoError(t, err)
	assert.False(t, res.Migrated)
	assert.Contains(t, res.Skipped, "/providers")
}

// An operator who already set updates_url has their value left alone.
func TestMigrateProvidersURLDoesNotOverwriteUpdatesURL(t *testing.T) {
	body := "providers_url: https://mirror.example.de/providers\nupdates_url: https://install.example.de\n"
	path := writeConfig(t, "mondoo.yml", body)

	res, err := MigrateProvidersURL()
	require.NoError(t, err)
	assert.False(t, res.Migrated)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, body, string(got))
}

func TestMigrateProvidersURLNothingToDo(t *testing.T) {
	writeConfig(t, "mondoo.yml", "space_mrn: //captain.api.mondoo.app/spaces/x\n")

	res, err := MigrateProvidersURL()
	require.NoError(t, err)
	assert.False(t, res.Migrated)
	assert.Contains(t, res.Skipped, "not set")
}

// A read-only config -- the normal state for a file owned by configuration
// management -- reports the error rather than pretending it migrated.
func TestMigrateProvidersURLReportsAnUnwritableConfig(t *testing.T) {
	path := writeConfig(t, "mondoo.yml", "providers_url: https://mirror.example.de/providers\n")
	require.NoError(t, os.Chmod(filepath.Dir(path), 0o500))
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(path), 0o700) })

	res, err := MigrateProvidersURL()
	require.Error(t, err)
	assert.False(t, res.Migrated)
}

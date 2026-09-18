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

// A value carrying a newline must not continue as further YAML and add settings
// of its own. providers_url reaches this from a config file or from
// MONDOO_PROVIDERS_URL, so a migration that concatenated it would turn a hostile
// or merely malformed value into real config keys.
func TestMigrateProvidersURLDoesNotInjectYAML(t *testing.T) {
	body := "providers_url: \"https://evil\\nspace_mrn: //attacker/providers\"\n"
	path := writeConfig(t, "mondoo.yml", body)

	_, err := MigrateProvidersURL()
	require.NoError(t, err)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(got), "\nspace_mrn: //attacker",
		"the newline continued as YAML and injected a setting")

	// Whatever was written has to leave the file parseable, and leave the key it
	// was not asked to touch alone.
	viper.Reset()
	viper.SetConfigFile(path)
	require.NoError(t, viper.ReadInConfig())
	assert.Empty(t, viper.GetString("space_mrn"))
}

// A value that is not an http(s) URL is reported rather than written.
func TestMigrateProvidersURLRejectsANonURL(t *testing.T) {
	writeConfig(t, "mondoo.yml", "providers_url: \"not a url/providers\"\n")

	res, err := MigrateProvidersURL()
	require.NoError(t, err)
	assert.False(t, res.Migrated)
	assert.Contains(t, res.Skipped, "http(s) URL")
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

// The migration replaces the file rather than editing in place, so the
// replacement has to carry the original's mode and owner. mondoo.yml holds the
// service account's private key and is routinely 0600 owned by the account the
// agent runs as; an admin migrating under sudo must not hand it to root and
// leave the agent unable to read it.
//
// The mode assertion bites anywhere. The owner assertion only bites where the
// migrating user is not the owner, which is the sudo case and not something a
// unit test can arrange without root -- run as the owner it is satisfied
// trivially. It is here so the intent is executable and a change that drops the
// chown is at least visible against a named expectation.
func TestMigrateProvidersURLPreservesModeAndOwner(t *testing.T) {
	path := writeConfig(t, "mondoo.yml", "providers_url: https://mirror.example.de/providers\n")
	require.NoError(t, os.Chmod(path, 0o600))

	before, err := os.Stat(path)
	require.NoError(t, err)
	beforeUID, beforeGID := ownerOf(t, before)

	res, err := MigrateProvidersURL()
	require.NoError(t, err)
	require.True(t, res.Migrated)

	after, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, before.Mode().Perm(), after.Mode().Perm(), "mode was not preserved")

	afterUID, afterGID := ownerOf(t, after)
	assert.Equal(t, beforeUID, afterUID, "owner was not preserved")
	assert.Equal(t, beforeGID, afterGID, "group was not preserved")
}

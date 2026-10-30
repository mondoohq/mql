// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package logindefs_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/logindefs"
)

func TestLoginDefsParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)

	f, err := mock.FileSystem().Open("/etc/login.defs")
	require.NoError(t, err)
	defer f.Close()

	entries := logindefs.Parse(f)

	assert.Equal(t, "tty", entries["TTYGROUP"])
	assert.Equal(t, "PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games", entries["ENV_PATH"])
	assert.Equal(t, "1", entries["PASS_MIN_DAYS"])

	_, ok := entries["SHA_CRYPT_MIN_ROUNDS"]
	assert.False(t, ok)
}

// shadow reads login.defs with getline(3), so the keys after a very long
// line still apply. A parser that stops there drops them, and a check such
// as params["PASS_MAX_DAYS"] != "99999" then passes on a missing key.
func TestLoginDefsParserKeepsKeysAfterLongLine(t *testing.T) {
	content := "PASS_MAX_DAYS 99999\n" +
		"MQL_LONG " + strings.Repeat("x", 70*1024) + "\n" +
		"UMASK 022\n" +
		"PASS_MIN_DAYS 0\n"

	entries := logindefs.Parse(strings.NewReader(content))
	assert.Equal(t, "99999", entries["PASS_MAX_DAYS"])
	assert.Len(t, entries["MQL_LONG"], 70*1024)
	assert.Equal(t, "022", entries["UMASK"])
	assert.Equal(t, "0", entries["PASS_MIN_DAYS"])
}

// Entries keeps every setting line with its number, including a key set twice,
// so a check can point at the line that sets a value.
func TestLoginDefsEntries(t *testing.T) {
	content := "# UMASK 000\nUMASK\t\t022\n\nPASS_MAX_DAYS 90 # policy\n  UMASK 027\nUMASK\n"

	assert.Equal(t, []logindefs.Entry{
		{Line: 2, Key: "UMASK", Value: "022"},
		{Line: 4, Key: "PASS_MAX_DAYS", Value: "90"},
		{Line: 5, Key: "UMASK", Value: "027"},
	}, logindefs.Entries(strings.NewReader(content)))
	assert.Equal(t, "027", logindefs.Parse(strings.NewReader(content))["UMASK"], "the last line wins")
}

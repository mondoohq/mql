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

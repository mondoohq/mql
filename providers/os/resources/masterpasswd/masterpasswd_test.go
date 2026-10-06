// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package masterpasswd_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/masterpasswd"
)

func parseFixture(t *testing.T, fixture string) ([]masterpasswd.Entry, []masterpasswd.LineError) {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/"+fixture))
	require.NoError(t, err)
	f, err := conn.FileSystem().Open("/etc/master.passwd")
	require.NoError(t, err)
	defer f.Close()
	entries, invalid, err := masterpasswd.Parse(f)
	require.NoError(t, err)
	return entries, invalid
}

func find(entries []masterpasswd.Entry, user string) *masterpasswd.Entry {
	for i := range entries {
		if entries[i].User == user {
			return &entries[i]
		}
	}
	return nil
}

func TestParseUpstreamDefaults(t *testing.T) {
	tests := []struct {
		fixture string
		count   int
		// root ships with an empty password field on all three; the installer
		// sets it.
		rootShell string
		rootClass string
	}{
		{"freebsd14.toml", 27, "/bin/sh", ""},
		{"openbsd7.toml", 69, "/bin/ksh", "daemon"},
		{"netbsd10.toml", 26, "/bin/sh", ""},
	}
	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			entries, invalid := parseFixture(t, tc.fixture)
			assert.Empty(t, invalid)
			assert.Len(t, entries, tc.count)

			root := find(entries, "root")
			require.NotNil(t, root)
			assert.Equal(t, int64(0), root.UID)
			assert.Equal(t, "", root.Password)
			assert.False(t, root.HasPassword())
			assert.Equal(t, tc.rootClass, root.Class)
			assert.Equal(t, tc.rootShell, root.Shell)
			assert.Nil(t, root.Change, "0 means the password never has to be changed")
			assert.Nil(t, root.Expire, "0 means the account never expires")
			assert.Equal(t, "Charlie &", root.Gecos)

			for _, e := range entries {
				if e.User == "root" {
					continue
				}
				assert.False(t, e.HasPassword(), e.User)
			}
		})
	}

	t.Run("freebsd14 toor has an empty shell", func(t *testing.T) {
		entries, _ := parseFixture(t, "freebsd14.toml")
		toor := find(entries, "toor")
		require.NotNil(t, toor)
		assert.Equal(t, "*", toor.Password)
		assert.Equal(t, "", toor.Shell)
		assert.Equal(t, "/root", toor.Home)
	})
}

func TestParseEdgeCases(t *testing.T) {
	entries, invalid := parseFixture(t, "edgecases.toml")

	users := []string{}
	for _, e := range entries {
		users = append(users, e.User)
	}
	assert.Equal(t, []string{"root", "alice", "bob", "carol"}, users)

	require.Len(t, invalid, 2)
	assert.Equal(t, 8, invalid[0].Line)
	assert.Contains(t, invalid[0].Error(), `invalid uid "abc"`)
	assert.Equal(t, 9, invalid[1].Line)
	assert.Contains(t, invalid[1].Error(), "expected 10 fields, got 9")
	assert.Nil(t, find(entries, "mallory"), "a bad uid must not turn into uid 0")

	root := find(entries, "root")
	require.NotNil(t, root)
	assert.Equal(t, 3, root.Line)
	assert.True(t, root.HasPassword())
	assert.False(t, root.Locked())

	alice := find(entries, "alice")
	require.NotNil(t, alice)
	assert.Equal(t, int64(1001), alice.UID)
	assert.Equal(t, int64(1001), alice.GID)
	assert.Equal(t, "", alice.Class)
	require.NotNil(t, alice.Change)
	assert.Equal(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), *alice.Change)
	require.NotNil(t, alice.Expire)
	assert.Equal(t, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), *alice.Expire)
	assert.True(t, alice.HasPassword())

	bob := find(entries, "bob")
	require.NotNil(t, bob)
	assert.True(t, bob.Locked())
	assert.False(t, bob.HasPassword())
	assert.Equal(t, "staff", bob.Class)
	assert.Equal(t, "/bin/csh", bob.Shell)

	carol := find(entries, "carol")
	require.NotNil(t, carol)
	assert.Equal(t, "", carol.Password)
	assert.False(t, carol.HasPassword())
	assert.False(t, carol.Locked())
}

func TestParseCommentsAndBlankLines(t *testing.T) {
	entries, invalid, err := masterpasswd.Parse(strings.NewReader("\n  # indented comment\n\r\n"))
	require.NoError(t, err)
	assert.Empty(t, entries)
	assert.Empty(t, invalid)
}

func TestParseRejectsBadNumbers(t *testing.T) {
	for name, line := range map[string]string{
		"gid":    "x:*:1:g::0:0:::",
		"change": "x:*:1:1::soon:0:::",
		"expire": "x:*:1:1::0:-:::",
		"name":   ":*:1:1::0:0:::",
		"extra":  "x:*:1:1::0:0::::",
	} {
		t.Run(name, func(t *testing.T) {
			entries, invalid, err := masterpasswd.Parse(strings.NewReader(line))
			require.NoError(t, err)
			assert.Empty(t, entries)
			assert.Len(t, invalid, 1)
		})
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package users_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/shadow"
	"go.mondoo.com/mql/providers/os/resources/users"
)

func TestParseEtcPasswdSkipsMalformedUidGid(t *testing.T) {
	// A line with a non-numeric uid/gid must be skipped, not surfaced as a
	// phantom uid 0 (root) account.
	const passwd = `root:x:0:0:root:/root:/bin/bash
broken:x:notanumber:1:broken uid:/home/broken:/bin/sh
brokengid:x:1001:notanumber:broken gid:/home/brokengid:/bin/sh
alice:x:1000:1000:Alice:/home/alice:/bin/bash
`

	m, err := users.ParseEtcPasswd(strings.NewReader(passwd))
	require.NoError(t, err)
	require.Equal(t, 2, len(m), "malformed uid/gid lines should be skipped")

	assert.Equal(t, "root", m[0].Name)
	assert.Equal(t, int64(0), m[0].Uid)
	assert.Equal(t, "alice", m[1].Name)
	assert.Equal(t, int64(1000), m[1].Uid)
	assert.Equal(t, int64(1000), m[1].Gid)
}

func TestParseLinuxEtcPasswd(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/debian.toml"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := mock.FileSystem().Open("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)
	defer f.Close()

	m, err := users.ParseEtcPasswd(f)
	assert.Nil(t, err)
	assert.Equal(t, 13, len(m), "detected the right amount of services")

	assert.Equal(t, "root", m[0].Name, "detected user name")
	assert.Equal(t, int64(0), m[0].Uid, "detected uid")
	assert.Equal(t, int64(0), m[0].Gid, "detected gid")
	assert.Equal(t, "root", m[0].Description, "user description")
	assert.Equal(t, "/root", m[0].Home, "detected user home")
	assert.Equal(t, "/bin/bash", m[0].Shell, "detected user shell")
}

func TestParseFreebsdLinuxEtcPasswd(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/freebsd12.toml"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := mock.FileSystem().Open("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)
	defer f.Close()

	m, err := users.ParseEtcPasswd(f)
	assert.Nil(t, err)
	assert.Equal(t, 28, len(m), "detected the right amount of services")

	assert.Equal(t, "root", m[0].Name, "detected user name")
	assert.Equal(t, int64(0), m[0].Uid, "detected uid")
	assert.Equal(t, int64(0), m[0].Gid, "detected gid")
	assert.Equal(t, "Charlie &", m[0].Description, "user description")
	assert.Equal(t, "/root", m[0].Home, "detected user home")
	assert.Equal(t, "/bin/csh", m[0].Shell, "detected user shell")
}

func TestParseLinuxGetentPasswd(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"os", "unix", "linux", "redhat"},
		},
	}, mock.WithPath("./testdata/oraclelinux_getent_passwd.toml"))
	require.NoError(t, err)
	m, err := users.ResolveManager(conn)
	require.Nil(t, err)

	list, err := m.List()
	require.Nil(t, err)
	assert.Equal(t, 20, len(list), "detected the right amount of users")

	assert.Equal(t, "root", list[0].Name, "detected user name")
	assert.Equal(t, int64(0), list[0].Uid, "detected uid")
	assert.Equal(t, int64(0), list[0].Gid, "detected gid")
	assert.Equal(t, "root", list[0].Description, "user description")
	assert.Equal(t, "/root", list[0].Home, "detected user home")
	assert.Equal(t, "/bin/bash", list[0].Shell, "detected user shell")
}

// 2026-10-01, day 20727 since the epoch.
var shadowNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func TestShadowAccountEnabled(t *testing.T) {
	tests := []struct {
		name  string
		entry shadow.ShadowEntry
		want  bool
	}{
		{"password hash", shadow.ShadowEntry{Password: "$y$j9T$QXjPV7Jc.bjCoIJb5OGOB/$chdD"}, true},
		{"empty password (passwd -S NP)", shadow.ShadowEntry{Password: ""}, true},
		{"locked hash (usermod -L)", shadow.ShadowEntry{Password: "!$y$j9T$iv4pmtK8LnIZYySmm8biZ0$GkNB"}, false},
		{"locked without hash", shadow.ShadowEntry{Password: "!"}, false},
		{"no password, star", shadow.ShadowEntry{Password: "*"}, false},
		{"systemd style !*", shadow.ShadowEntry{Password: "!*"}, false},
		{"solaris *LK*", shadow.ShadowEntry{Password: "*LK*"}, false},
		{"expired 2020-01-01", shadow.ShadowEntry{Password: "$y$hash", ExpiryDates: "18262"}, false},
		{"expires today", shadow.ShadowEntry{Password: "$y$hash", ExpiryDates: "20727"}, false},
		{"expires tomorrow", shadow.ShadowEntry{Password: "$y$hash", ExpiryDates: "20728"}, true},
		{"expiry 0 means none in shadow-utils", shadow.ShadowEntry{Password: "$y$hash", ExpiryDates: "0"}, true},
		{"unparsable expiry ignored", shadow.ShadowEntry{Password: "$y$hash", ExpiryDates: "never"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, users.ShadowAccountEnabled(tc.entry, shadowNow))
		})
	}
}

func TestApplyShadowEnabledUnreadableShadow(t *testing.T) {
	list := []*users.User{{Name: "root"}, {Name: "alice"}}
	users.ApplyShadowEnabled(list, nil, shadowNow)
	for _, u := range list {
		assert.True(t, u.EnabledUnknown, u.Name)
		assert.False(t, u.Enabled, u.Name)
	}
}

func TestUnixUserManagerEnabledFromShadow(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"os", "unix", "linux", "debian", "ubuntu"}},
	}, mock.WithPath("./testdata/ubuntu2404_shadow.toml"))
	require.NoError(t, err)
	m, err := users.ResolveManager(conn)
	require.NoError(t, err)

	list, err := m.List()
	require.NoError(t, err)
	got := map[string]*users.User{}
	for _, u := range list {
		got[u.Name] = u
	}
	require.Len(t, got, 8)

	for name, want := range map[string]bool{
		"root":            false,
		"systemd-network": false,
		"ubuntu":          false,
		"mqlt_bash":       true,
		"mqlt_locked":     false,
		"mqlt_nopw":       true,
		"mqlt_expire":     false,
	} {
		assert.False(t, got[name].EnabledUnknown, name)
		assert.Equal(t, want, got[name].Enabled, name)
	}

	// An account with no shadow entry (directory service) is unknown.
	assert.True(t, got["ldapuser"].EnabledUnknown)
}

func TestUnixUserManagerNoShadowIsUnknown(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"os", "unix", "linux", "debian"}},
	}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)
	m, err := users.ResolveManager(conn)
	require.NoError(t, err)

	list, err := m.List()
	require.NoError(t, err)
	require.NotEmpty(t, list)
	for _, u := range list {
		assert.True(t, u.EnabledUnknown, u.Name)
	}
}

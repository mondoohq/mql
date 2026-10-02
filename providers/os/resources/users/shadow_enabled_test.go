// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package users_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/shadow"
	"go.mondoo.com/mql/providers/os/resources/users"
)

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

func TestOSXUserManagerEnabledIsUnknown(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"os", "unix", "darwin"}},
	}, mock.WithPath("./testdata/osx.toml"))
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

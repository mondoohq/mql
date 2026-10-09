// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func TestSudoersPathsForPlatform(t *testing.T) {
	tests := []struct {
		platform string
		expected []string
	}{
		{"freebsd", []string{"/usr/local/etc/sudoers"}},
		{"dragonflybsd", []string{"/usr/local/etc/sudoers"}},
		{"openbsd", []string{"/usr/local/etc/sudoers"}},
		{"netbsd", []string{"/usr/pkg/etc/sudoers"}},
		{"aix", []string{"/etc/sudoers", "/opt/freeware/etc/sudoers"}},
		{"debian", []string{"/etc/sudoers"}},
		{"ubuntu", []string{"/etc/sudoers"}},
		{"redhat", []string{"/etc/sudoers"}},
		{"macos", []string{"/etc/sudoers"}},
	}

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			assert.Equal(t, tt.expected, sudoersPathsForPlatform(connWithPlatform(tt.platform)))
		})
	}

	t.Run("nil platform", func(t *testing.T) {
		conn := &mockConn{asset: &inventory.Asset{}}
		assert.Equal(t, []string{"/etc/sudoers"}, sudoersPathsForPlatform(conn))
	})
}

// A Defaults line with a comma-separated list yields one sudoers.default per
// setting, each with the line's file, number and raw text.
func TestSudoersDefaultsList(t *testing.T) {
	fixturePath, err := filepath.Abs("testdata/sudoers_defaults_freebsd.toml")
	require.NoError(t, err)

	asset := &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "freebsd",
			Family: []string{"bsd", "unix"},
		},
	}
	conn, err := mock.New(0, asset, mock.WithPath(fixturePath))
	require.NoError(t, err)

	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
	raw, err := CreateResource(runtime, "sudoers", nil)
	require.NoError(t, err)

	defaults := raw.(*mqlSudoers).GetDefaults()
	require.NoError(t, defaults.Error)

	type setting struct {
		line      int64
		scope     string
		target    string
		parameter string
		value     string
		operation string
		negated   bool
	}
	var got []setting
	ids := map[string]bool{}
	for _, d := range defaults.Data {
		def := d.(*mqlSudoersDefault)
		got = append(got, setting{
			def.LineNumber.Data, def.Scope.Data, def.Target.Data, def.Parameter.Data,
			def.Value.Data, def.Operation.Data, def.Negated.Data,
		})
		ids[def.__id] = true
	}
	assert.Equal(t, []setting{
		{2, "global", "", "env_reset", "", "", false},
		{2, "global", "", "timestamp_timeout", "15", "=", false},
		{3, "global", "", "use_pty", "", "", false},
		{3, "global", "", "logfile", "/var/log/sudo.log", "=", false},
		{4, "user", "%wheel", "lecture", "", "", true},
		{4, "user", "%wheel", "passwd_tries", "2", "=", false},
		{5, "command", "/usr/sbin/pkg", "env_keep", "PKG_DBDIR, PKG_CACHEDIR", "+=", false},
	}, got)
	// every setting is its own resource, not the cached first one of its line
	assert.Len(t, ids, 7)
	assert.Equal(t, "Defaults env_reset, timestamp_timeout=15",
		defaults.Data[1].(*mqlSudoersDefault).Raw.Data)
}

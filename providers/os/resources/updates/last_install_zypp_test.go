// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func readZyppFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return string(data)
}

// The Leap 16.0 history: an image build, four `zypper install` runs that flip
// dozens of patches to applied, an `--oldpackage` kernel install and its
// removal, then `zypper up ca-certificates-mozilla`, which installed the
// package at 15:07:03 and logged its patch as applied at 15:07:04.
func TestParseZyppHistory_Leap16(t *testing.T) {
	update, err := ParseZyppHistory(strings.NewReader(readZyppFixture(t, "zypp-history-leap16.txt")), time.UTC)
	require.NoError(t, err)
	require.NotNil(t, update)
	// The run's last install, not the patch line a second later and not any
	// of the install runs after which patches also read applied.
	assert.Equal(t, time.Date(2026, 10, 2, 15, 7, 3, 0, time.UTC), update.Time)
	assert.Equal(t, LastUpdateSourceZyppHistory, update.Source)
}

// The SLES 16.0 history holds only install and remove runs, yet logs
// needed->applied security patches after two of them. None of it is an update.
func TestParseZyppHistory_Sles16InstallsOnly(t *testing.T) {
	update, err := ParseZyppHistory(strings.NewReader(readZyppFixture(t, "zypp-history-sles16.txt")), time.UTC)
	require.NoError(t, err)
	assert.Nil(t, update)
}

// libzypp writes local time with no zone.
func TestParseZyppHistory_AssetZone(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	require.NoError(t, err)
	update, err := ParseZyppHistory(strings.NewReader(readZyppFixture(t, "zypp-history-leap16.txt")), ny)
	require.NoError(t, err)
	require.NotNil(t, update)
	assert.Equal(t, time.Date(2026, 10, 2, 19, 7, 3, 0, time.UTC), update.Time)
}

func TestParseZyppHistory_Runs(t *testing.T) {
	t.Run("newest update run wins over a later install run", func(t *testing.T) {
		log := `2026-03-01 10:00:00|command|root@localhost|'zypper' '-n' 'patch'|
2026-03-01 10:00:05|install|openssl-3|3.1.4-1.1|x86_64||repo-update|abc|
2026-03-01 10:00:09|install|libopenssl3|3.1.4-1.1|x86_64||repo-update|abc|
2026-03-02 10:00:00|command|root@localhost|'zypper' '-n' 'dup'|
2026-03-02 10:01:00|install|bash|5.2-1.1|x86_64||repo-oss|abc|
2026-03-03 10:00:00|command|root@localhost|'zypper' 'in' 'vim'|
2026-03-03 10:00:02|install|vim|9.1-1.1|x86_64|root@localhost|repo-oss|abc|
`
		update, err := ParseZyppHistory(strings.NewReader(log), time.UTC)
		require.NoError(t, err)
		require.NotNil(t, update)
		assert.Equal(t, time.Date(2026, 3, 2, 10, 1, 0, 0, time.UTC), update.Time)
	})

	t.Run("an update run that installed nothing is no update", func(t *testing.T) {
		log := `2026-03-01 10:00:00|command|root@localhost|'zypper' '-n' 'up'|
2026-03-01 10:00:01|remove |oldpkg|1-1|x86_64|root@localhost|
2026-03-01 10:00:02|patch  |SUSE-2026-1|1|noarch|repo-update|important|security|needed|applied|
`
		update, err := ParseZyppHistory(strings.NewReader(log), time.UTC)
		require.NoError(t, err)
		assert.Nil(t, update)
	})

	t.Run("installs before any command line are not attributable", func(t *testing.T) {
		log := `2026-03-01 10:00:01|install|bash|5.2-1.1|x86_64||repo-oss|abc|
`
		update, err := ParseZyppHistory(strings.NewReader(log), time.UTC)
		require.NoError(t, err)
		assert.Nil(t, update)
	})
}

func TestIsZyppUpdateCommandline(t *testing.T) {
	cases := map[string]bool{
		`'zypper' '-n' '--no-refresh' 'up' '--no-recommends' 'ca-certificates-mozilla'`: true,
		`'zypper' 'update'`: true,
		`'zypper' '--non-interactive' 'patch' '--updatestack-only'`: true,
		`'/usr/bin/zypper' '-n' 'dup'`:                              true,
		`'zypper' 'dist-upgrade'`:                                   true,
		`'zypper' '--root' '/mnt' 'up'`:                             true,
		`'zypper' '-R' 'patch' 'in' 'vim'`:                          false,
		`'zypper' '-n' '--no-refresh' 'in' '--oldpackage' '--no-recommends' 'kernel-default-6.12.0-160000.37.1'`:            false,
		`'zypper' '--non-interactive' 'install' '--no-recommends' 'patch'`:                                                  false,
		`'zypper' '-n' 'rm' '--clean-deps' 'kernel-default-6.12.0-160000.37.1'`:                                             false,
		`'/usr/lib/YaST2/bin/y2start' 'sw_single' 'patch'`:                                                                  false,
		`'zypper' '--non-interactive' '--gpg-auto-import-keys' '--pkg-cache-dir' '/var/cache/kiwi/packages' 'install' 'up'`: false,
		`'zypper'`: false,
	}
	for cmdline, want := range cases {
		assert.Equal(t, want, isZyppUpdateCommandline(cmdline), cmdline)
	}
}

func TestSplitZyppCommandline(t *testing.T) {
	assert.Equal(t, []string{"zypper", "it's", "a b"}, splitZyppCommandline(`'zypper' 'it'\''s' 'a b'`))
}

func TestLastInstalledZyppFS(t *testing.T) {
	const run = `2026-03-01 10:00:00|command|root@localhost|'zypper' '-n' 'up'|
2026-03-01 10:00:05|install|bash|5.2-1.1|x86_64||repo-oss|abc|
`
	const installOnly = `2026-04-01 10:00:00|command|root@localhost|'zypper' 'in' 'vim'|
2026-04-01 10:00:02|install|vim|9.1-1.1|x86_64|root@localhost|repo-oss|abc|
`
	want := time.Date(2026, 3, 1, 10, 0, 5, 0, time.UTC)

	t.Run("no history is null", func(t *testing.T) {
		update, err := lastInstalledZyppFS(afero.NewMemMapFs(), time.UTC)
		require.NoError(t, err)
		assert.Nil(t, update)
	})

	t.Run("the live log answers", func(t *testing.T) {
		mfs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(mfs, zyppHistoryPath, []byte(run), 0o644))
		update, err := lastInstalledZyppFS(mfs, time.UTC)
		require.NoError(t, err)
		require.NotNil(t, update)
		assert.Equal(t, want, update.Time)
	})

	// logrotate runs with nocreate and xz, so right after a rotation the
	// live log is gone and the run sits in history-<date>.xz.
	t.Run("an xz rotation answers when the live log has no run", func(t *testing.T) {
		mfs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(mfs, zyppHistoryPath, []byte(installOnly), 0o644))
		var buf bytes.Buffer
		w, err := xz.NewWriter(&buf)
		require.NoError(t, err)
		_, err = w.Write([]byte(run))
		require.NoError(t, err)
		require.NoError(t, w.Close())
		require.NoError(t, afero.WriteFile(mfs, zyppHistoryDir+"/history-20260315.xz", buf.Bytes(), 0o644))
		// An older copy with a newer-looking run must not win over the
		// newer copy.
		older := strings.ReplaceAll(run, "2026-03-01", "2025-01-01")
		require.NoError(t, afero.WriteFile(mfs, zyppHistoryDir+"/history-20250101", []byte(older), 0o644))

		update, err := lastInstalledZyppFS(mfs, time.UTC)
		require.NoError(t, err)
		require.NotNil(t, update)
		assert.Equal(t, want, update.Time)
	})

	t.Run("a refused read is forbidden with structured errors", func(t *testing.T) {
		t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })
		denied := deniedFs{afero.NewMemMapFs()}

		plugin.ReadFeatures([]byte(mql.Features{byte(mql.StructuredErrors)}))
		update, err := lastInstalledZyppFS(denied, time.UTC)
		assert.Nil(t, update)
		require.Error(t, err)
		assert.True(t, errors.Is(err, llx.ErrForbidden), "got %v", err)

		plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)}))
		update, err = lastInstalledZyppFS(denied, time.UTC)
		assert.NoError(t, err)
		assert.Nil(t, update)
	})
}

// deniedFs refuses every open, the way a non-root scan meets the 0750
// /var/log/zypp.
type deniedFs struct{ afero.Fs }

func (d deniedFs) Open(name string) (afero.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
}

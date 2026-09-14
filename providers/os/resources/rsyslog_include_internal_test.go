// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/mock"
	"go.mondoo.com/mql/v13/utils/syncx"
)

// rsyslogFixtureFiles resolves rsyslog.conf.files against the include fixture
// and returns the paths it reports.
func rsyslogFixtureFiles(t *testing.T) []string {
	t.Helper()
	return rsyslogFixtureFilesFrom(t, "testdata/rsyslog_includes.toml")
}

// rsyslogFixtureFilesFrom resolves rsyslog.conf.files against an arbitrary
// mock fixture and returns the file paths it reports.
func rsyslogFixtureFilesFrom(t *testing.T, fixture string) []string {
	t.Helper()

	fixturePath, err := filepath.Abs(fixture)
	require.NoError(t, err)

	asset := &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "arch",
			Family: []string{"linux", "unix"},
		},
	}
	conn, err := mock.New(0, asset, mock.WithPath(fixturePath))
	require.NoError(t, err)

	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}

	raw, err := CreateResource(runtime, "rsyslog.conf", map[string]*llx.RawData{
		"path": llx.StringData("/etc/rsyslog.conf"),
	})
	require.NoError(t, err)

	files := raw.(*mqlRsyslogConf).GetFiles()
	require.NoError(t, files.Error)

	paths := make([]string, 0, len(files.Data))
	for _, f := range files.Data {
		paths = append(paths, f.(*mqlFile).Path.Data)
	}
	return paths
}

// $IncludeConfig patterns are globs, and they have to resolve for directories
// other than the conventional `<conf>.d` — that one is also picked up by the
// legacy fallback, which masks a broken include expansion.
func TestRsyslogConf_IncludeExpansion(t *testing.T) {
	paths := rsyslogFixtureFiles(t)

	t.Run("reports every included file exactly once", func(t *testing.T) {
		assert.ElementsMatch(t, []string{
			"/etc/rsyslog.conf",
			"/etc/rsyslog.d/50-default.conf",
			"/etc/rsyslog.extra/10-site.conf",
			"/etc/rsyslog.single.conf",
			"/etc/rsyslog.deep/90-deep.conf",
		}, paths)
	})

	t.Run("expands a glob outside the conventional .d directory", func(t *testing.T) {
		assert.Contains(t, paths, "/etc/rsyslog.extra/10-site.conf")
	})

	t.Run("applies the glob to the listing", func(t *testing.T) {
		assert.NotContains(t, paths, "/etc/rsyslog.extra/notes.txt",
			"notes.txt shares the directory but does not match *.conf")
	})

	t.Run("an exact include pulls in only the named file", func(t *testing.T) {
		assert.Contains(t, paths, "/etc/rsyslog.single.conf")
		assert.NotContains(t, paths, "/etc/other.conf",
			"other.conf shares /etc with the include target but was not named")
	})

	t.Run("follows includes nested inside a fragment", func(t *testing.T) {
		assert.Contains(t, paths, "/etc/rsyslog.deep/90-deep.conf")
	})

	t.Run("skips an include pointing at a missing directory", func(t *testing.T) {
		// /etc/rsyslog.absent has no recorded listing. The walk must carry on
		// and still report the files it could resolve.
		for _, p := range paths {
			assert.NotContains(t, p, "rsyslog.absent")
		}
		assert.Contains(t, paths, "/etc/rsyslog.conf")
	})
}

// A wildcard in a non-terminal path segment (`/etc/rsyslog.apps/*/out.conf`)
// must fan out across every matching subdirectory. Previously the middle glob
// was handed to the directory search verbatim and matched nothing, so no
// fragment was ever included.
func TestRsyslogConf_MidPathIncludeGlob(t *testing.T) {
	paths := rsyslogFixtureFilesFrom(t, "testdata/rsyslog_midpath_include.toml")

	t.Run("expands the wildcard across every subdirectory", func(t *testing.T) {
		assert.ElementsMatch(t, []string{
			"/etc/rsyslog.conf",
			"/etc/rsyslog.apps/web/out.conf",
			"/etc/rsyslog.apps/db/out.conf",
		}, paths)
	})

	t.Run("applies the basename glob inside each matched subdirectory", func(t *testing.T) {
		assert.NotContains(t, paths, "/etc/rsyslog.apps/web/other.conf",
			"other.conf shares the directory but does not match out.conf")
	})
}

func TestRsyslogIncludeMatches(t *testing.T) {
	tests := []struct {
		name  string
		glob  string
		match []string // full paths that should match
		miss  []string // full paths that should NOT match
	}{
		{
			name:  "star",
			glob:  "*.conf",
			match: []string{"/etc/rsyslog.d/foo.conf", "/etc/rsyslog.d/00-local.conf", "/etc/rsyslog.d/.conf"},
			miss:  []string{"/etc/rsyslog.d/foo.conf.bak", "/etc/rsyslog.d/foo"},
		},
		{
			name:  "question mark",
			glob:  "0?-local.conf",
			match: []string{"/etc/rsyslog.d/00-local.conf", "/etc/rsyslog.d/0a-local.conf"},
			miss:  []string{"/etc/rsyslog.d/000-local.conf", "/etc/rsyslog.d/0-local.conf"},
		},
		{
			name:  "character class",
			glob:  "[0-9]*.conf",
			match: []string{"/etc/rsyslog.d/0foo.conf", "/etc/rsyslog.d/9.conf"},
			miss:  []string{"/etc/rsyslog.d/afoo.conf"},
		},
		{
			name:  "regex metacharacters in the pattern are literal",
			glob:  "foo.bar+.conf",
			match: []string{"/etc/rsyslog.d/foo.bar+.conf"},
			miss:  []string{"/etc/rsyslog.d/fooxbar+.conf", "/etc/rsyslog.d/foo.bar.conf"},
		},
		{
			name:  "no metas",
			glob:  "local.conf",
			match: []string{"/etc/rsyslog.d/local.conf"},
			miss:  []string{"/etc/rsyslog.d/localxconf", "/etc/rsyslog.d/local.conf.bak"},
		},
		{
			name:  "matches the basename, not the directory",
			glob:  "*.conf",
			match: []string{"/etc/rsyslog.d/sub/foo.conf", "/foo.conf"},
			miss:  []string{"/etc/foo.conf/bar"},
		},
		{
			name:  "malformed glob matches nothing",
			glob:  "[",
			match: nil,
			miss:  []string{"/etc/rsyslog.d/[", "/etc/rsyslog.d/foo.conf"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, m := range tt.match {
				assert.True(t, rsyslogIncludeMatches(tt.glob, m), "expected %q to match glob %q", m, tt.glob)
			}
			for _, m := range tt.miss {
				assert.False(t, rsyslogIncludeMatches(tt.glob, m), "expected %q NOT to match glob %q", m, tt.glob)
			}
		})
	}
}

// A fragment reached only through `<conf>.d` auto-discovery must still have its
// own includes followed. The sweep used to append such fragments as leaves, so
// anything they included was silently missing from rsyslog.conf.files.
func TestRsyslogConf_DotDFragmentIncludesAreFollowed(t *testing.T) {
	paths := rsyslogFixtureFilesFrom(t, "testdata/rsyslog_dotd_nested.toml")

	assert.Contains(t, paths, "/etc/rsyslog.conf")
	assert.Contains(t, paths, "/etc/rsyslog.d/50-frag.conf",
		"the fragment is found by .d auto-discovery")
	assert.Contains(t, paths, "/etc/rsyslog.nested/90-nested.conf",
		"the fragment's own $IncludeConfig must be followed")
	assert.NotContains(t, paths, "/etc/rsyslog.nested/notes.txt",
		"the include glob still applies to the nested directory")
}

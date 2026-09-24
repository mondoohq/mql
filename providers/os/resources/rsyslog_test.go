// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// content() must skip files it cannot read instead of swallowing the error and
// appending an empty block for them.
func TestRsyslogConfContentSkipsUnreadableFiles(t *testing.T) {
	good := &mqlFile{}
	good.Content = plugin.TValue[string]{Data: "good content", State: plugin.StateIsSet}

	unreadable := &mqlFile{}
	unreadable.Content = plugin.TValue[string]{
		Error: errors.New("permission denied"),
		State: plugin.StateIsSet | plugin.StateIsNull,
	}

	s := &mqlRsyslogConf{}
	out, err := s.content([]any{unreadable, good})
	require.NoError(t, err)

	// The unreadable file is skipped entirely; only the readable file's content
	// is emitted (previously a spurious leading blank line was appended).
	assert.Equal(t, "good content\n", out)
}

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

func TestRsyslogConfPath(t *testing.T) {
	tests := []struct {
		platform string
		expected string
	}{
		{"freebsd", "/usr/local/etc/rsyslog.conf"},
		{"dragonflybsd", "/usr/local/etc/rsyslog.conf"},
		{"openbsd", "/usr/local/etc/rsyslog.conf"},
		{"netbsd", "/usr/pkg/etc/rsyslog.conf"},
		{"debian", "/etc/rsyslog.conf"},
		{"ubuntu", "/etc/rsyslog.conf"},
		{"redhat", "/etc/rsyslog.conf"},
		{"macos", "/etc/rsyslog.conf"},
		{"aix", "/etc/rsyslog.conf"},
		{"solaris", "/etc/rsyslog.conf"},
	}

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			assert.Equal(t, tt.expected, rsyslogConfPath(connWithPlatform(tt.platform)))
		})
	}

	t.Run("nil platform", func(t *testing.T) {
		conn := &mockConn{asset: &inventory.Asset{}}
		assert.Equal(t, "/etc/rsyslog.conf", rsyslogConfPath(conn))
	})
}

func TestStripRsyslogComment(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no comment", "$ModLoad imuxsock", "$ModLoad imuxsock"},
		{"trailing comment", "$ModLoad imuxsock # load unix socket input", "$ModLoad imuxsock "},
		{"whole line comment", "# this is a comment", ""},
		{"comment in double-quoted string is preserved", `$Template foo,"hash#tag"`, `$Template foo,"hash#tag"`},
		{"comment in single-quoted string is preserved", `$Template foo,'hash#tag'`, `$Template foo,'hash#tag'`},
		{"comment after closing quote is stripped", `$Template foo,"value" # comment`, `$Template foo,"value" `},
		{"blank line", "", ""},
		{"escaped hash is NOT special (rsyslog rule, not shell)", `key=val#after`, `key=val`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, stripRsyslogComment(tt.in))
		})
	}
}

func TestRsyslogConfParams(t *testing.T) {
	s := &mqlRsyslogConf{}

	content := strings.Join([]string{
		"# rsyslog configuration",
		"$FileCreateMode 0640",
		"$FileOwner   syslog",  // extra spacing is trimmed
		"$DirCreateMode\t0755", // tab separator
		"$FileGroup adm # inline comment is stripped",
		"module(load=\"imuxsock\")", // modern syntax is ignored
		"*.info /var/log/messages",  // selector lines are ignored
		"$FileCreateMode 0600",      // duplicate: last occurrence wins
		"$ActionResumeRetryCount",   // bare directive with no value is skipped
	}, "\n")

	got, err := s.params(content)
	assert.NoError(t, err)
	assert.Equal(t, map[string]any{
		"FileCreateMode": "0600",
		"FileOwner":      "syslog",
		"DirCreateMode":  "0755",
		"FileGroup":      "adm",
	}, got)
}

func TestParseRsyslogIncludes(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "empty",
			content: "",
			want:    nil,
		},
		{
			name:    "only directives unrelated to includes",
			content: "$ModLoad imuxsock\n$ActionFileDefaultTemplate foo\n",
			want:    nil,
		},
		{
			name:    "legacy $IncludeConfig with glob",
			content: "$IncludeConfig /etc/rsyslog.d/*.conf\n",
			want:    []string{"/etc/rsyslog.d/*.conf"},
		},
		{
			name:    "legacy directive is case-insensitive",
			content: "$includeconfig /etc/rsyslog.d/a.conf\n$INCLUDECONFIG /etc/rsyslog.d/b.conf\n",
			want:    []string{"/etc/rsyslog.d/a.conf", "/etc/rsyslog.d/b.conf"},
		},
		{
			name:    "legacy with trailing inline comment",
			content: "$IncludeConfig /etc/rsyslog.d/*.conf # load fragments\n",
			want:    []string{"/etc/rsyslog.d/*.conf"},
		},
		{
			name:    "legacy with quoted value",
			content: `$IncludeConfig "/etc/rsyslog.d/*.conf"` + "\n",
			want:    []string{"/etc/rsyslog.d/*.conf"},
		},
		{
			name:    "modern include() with file=",
			content: `include(file="/etc/rsyslog.d/*.conf")` + "\n",
			want:    []string{"/etc/rsyslog.d/*.conf"},
		},
		{
			name:    "modern include() with extra params",
			content: `include(file="/etc/rsyslog.d/*.conf" mode="optional")` + "\n",
			want:    []string{"/etc/rsyslog.d/*.conf"},
		},
		{
			name:    "modern include() with single-quoted value",
			content: `include(file='/etc/rsyslog.d/*.conf')` + "\n",
			want:    []string{"/etc/rsyslog.d/*.conf"},
		},
		{
			name:    "modern include() with unquoted value",
			content: `include(file=/etc/rsyslog.d/local.conf)` + "\n",
			want:    []string{"/etc/rsyslog.d/local.conf"},
		},
		{
			name:    "modern include() with text= is skipped",
			content: `include(text="ruleset(name=\"foo\") { /* ... */ }")` + "\n",
			want:    nil,
		},
		{
			name: "mixed legacy + modern + ignored directives",
			content: `# rsyslog.conf
$ModLoad imuxsock

$IncludeConfig /etc/rsyslog.d/00-local.conf
include(file="/etc/rsyslog.d/*.conf")
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
`,
			want: []string{"/etc/rsyslog.d/00-local.conf", "/etc/rsyslog.d/*.conf"},
		},
		{
			name: "duplicates collapse, source order preserved",
			content: `$IncludeConfig /a.conf
$IncludeConfig /b.conf
$IncludeConfig /a.conf
include(file="/b.conf")
`,
			want: []string{"/a.conf", "/b.conf"},
		},
		{
			name:    "false positive guard: $IncludeConfigSomething is not a match",
			content: "$IncludeConfigSomething /tmp/x.conf\n",
			want:    nil,
		},
		{
			name:    "false positive guard: includes inside a comment are ignored",
			content: "# example: $IncludeConfig /etc/rsyslog.d/*.conf\n",
			want:    nil,
		},
		{
			name:    "comment inside quoted include arg is preserved",
			content: `include(file="/etc/rsyslog.d/has#hash.conf")` + "\n",
			want:    []string{"/etc/rsyslog.d/has#hash.conf"},
		},
		{
			name: "modern include() multi-line block (Ansible-style)",
			content: `include(
    file="/etc/rsyslog.d/*.conf"
)
`,
			want: []string{"/etc/rsyslog.d/*.conf"},
		},
		{
			name: "modern include() multi-line with mode after",
			content: `include(
    file="/etc/rsyslog.d/*.conf"
    mode="optional"
)
`,
			want: []string{"/etc/rsyslog.d/*.conf"},
		},
		{
			name: "modern include() opens and closes mid-line",
			content: `include( file="/etc/rsyslog.d/a.conf" )
include(file="/etc/rsyslog.d/b.conf"
)
`,
			want: []string{"/etc/rsyslog.d/a.conf", "/etc/rsyslog.d/b.conf"},
		},
		{
			// Unterminated blocks have no closing `)`, so the anchored
			// regex won't match. Returning nil is correct — rsyslog itself
			// would reject this config at load time. We surface nothing
			// rather than guessing at a partial parse.
			name: "unterminated include() block returns nothing",
			content: `include(
    file="/etc/rsyslog.d/orphan.conf"
`,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRsyslogIncludes(tt.content)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCoalesceIncludeBlocks(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "blank lines outside blocks are dropped",
			in:   "$ModLoad imuxsock\n\n\n$IncludeConfig /etc/rsyslog.d/x.conf\n",
			want: []string{"$ModLoad imuxsock", "$IncludeConfig /etc/rsyslog.d/x.conf"},
		},
		{
			name: "comments are stripped before coalescing",
			in:   "include( # opens\n  file=\"/a.conf\" # path\n) # closes\n",
			want: []string{`include( file="/a.conf" )`},
		},
		{
			name: "parens inside quotes do not affect block tracking",
			in:   `include(file="/a.conf"  text=")")` + "\n",
			want: []string{`include(file="/a.conf"  text=")")`},
		},
		{
			name: "non-include line with stray paren is not coalesced",
			in:   "$Template foo,\"(literal)\"\n$IncludeConfig /a.conf\n",
			want: []string{`$Template foo,"(literal)"`, "$IncludeConfig /a.conf"},
		},
		{
			name: "blank lines INSIDE a block are kept as separators",
			in:   "include(\n\n    file=\"/a.conf\"\n\n)\n",
			want: []string{`include(  file="/a.conf"  )`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := coalesceIncludeBlocks(tt.in)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCountUnquotedParens(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"include(", 1},
		{`include(file="/a")`, 0},
		{`include(file="/a"`, 1},
		{"))))", -4},
		{`"()()"`, 0},
		{`'()'`, 0},
		{`(text=")")`, 0},
		{`(text="(")`, 0},
		{`'(' "(" (`, 1}, // only the third `(` is unquoted
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, countUnquotedParens(tt.in))
		})
	}
}

func TestResolveRsyslogInclude(t *testing.T) {
	tests := []struct {
		name      string
		parentDir string
		pattern   string
		wantDir   string
		wantGlob  string
	}{
		{
			name:      "absolute path with glob",
			parentDir: "/etc",
			pattern:   "/etc/rsyslog.d/*.conf",
			wantDir:   "/etc/rsyslog.d",
			wantGlob:  "*.conf",
		},
		{
			name:      "absolute path with no glob",
			parentDir: "/etc",
			pattern:   "/etc/rsyslog.d/00-local.conf",
			wantDir:   "/etc/rsyslog.d",
			wantGlob:  "00-local.conf",
		},
		{
			name:      "relative path is anchored at parent dir",
			parentDir: "/etc/rsyslog.d",
			pattern:   "local.conf",
			wantDir:   "/etc/rsyslog.d",
			wantGlob:  "local.conf",
		},
		{
			name:      "relative path with subdir",
			parentDir: "/etc/rsyslog.d",
			pattern:   "extras/local.conf",
			wantDir:   "/etc/rsyslog.d/extras",
			wantGlob:  "local.conf",
		},
		{
			name:      "relative path with glob",
			parentDir: "/etc/rsyslog.d",
			pattern:   "extras/*.conf",
			wantDir:   "/etc/rsyslog.d/extras",
			wantGlob:  "*.conf",
		},
		{
			name:      "glob metacharacters are left intact for the matcher",
			parentDir: "/etc",
			pattern:   "/etc/rsyslog.d/[0-9]?-local.conf",
			wantDir:   "/etc/rsyslog.d",
			wantGlob:  "[0-9]?-local.conf",
		},
		{
			name:      "parent traversal is cleaned",
			parentDir: "/etc/rsyslog.d",
			pattern:   "../rsyslog.extra/*.conf",
			wantDir:   "/etc/rsyslog.extra",
			wantGlob:  "*.conf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, glob := resolveRsyslogInclude(tt.parentDir, tt.pattern)
			assert.Equal(t, tt.wantDir, dir)
			assert.Equal(t, tt.wantGlob, glob)
		})
	}
}

// rsyslogFixtureConf resolves rsyslog.conf against a mock fixture.
func rsyslogFixtureConf(t *testing.T, fixture string) *mqlRsyslogConf {
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
	return raw.(*mqlRsyslogConf)
}

func TestRsyslogConf_SelectorModernAction(t *testing.T) {
	conf := rsyslogFixtureConf(t, "testdata/rsyslog_forwarding.toml")

	actions := conf.GetActions()
	require.NoError(t, actions.Error)
	var fwd *mqlRsyslogAction
	for _, a := range actions.Data {
		act := a.(*mqlRsyslogAction)
		assert.NotContains(t, act.Target.Data, "action(", "the action() text must not become a target")
		if act.Type.Data == "omfwd" {
			fwd = act
		}
	}
	require.NotNil(t, fwd, "the *.* action(type=\"omfwd\") statement must surface as an omfwd action")
	assert.Equal(t, "logs.example.com", fwd.Target.Data)
	assert.Equal(t, "tcp", fwd.Protocol.Data)
	assert.Equal(t, "100", fwd.Parameters.Data.(map[string]any)["action.resumeretrycount"])
	assert.Equal(t, "LinkedList", fwd.Queue.Data.(map[string]any)["type"])
	assert.Equal(t, "1000", fwd.Queue.Data.(map[string]any)["size"])
	assert.Equal(t, 3, int(fwd.SourceLine.Data))

	rules := conf.GetRules()
	require.NoError(t, rules.Error)
	require.Len(t, rules.Data, 3, "*.*, auth+authpriv, local7")

	t.Run("the selector's rule resolves to the same action resource", func(t *testing.T) {
		all := rules.Data[0].(*mqlRsyslogRule)
		assert.Equal(t, []any{"*"}, all.Facilities.Data)
		act := all.GetAction()
		require.NoError(t, act.Error)
		require.NotNil(t, act.Data)
		assert.Same(t, fwd, act.Data)
	})

	t.Run("a legacy rule resolves to its parsed action", func(t *testing.T) {
		auth := rules.Data[1].(*mqlRsyslogRule)
		act := auth.GetAction()
		require.NoError(t, act.Error)
		require.NotNil(t, act.Data)
		assert.Equal(t, "omfile", act.Data.Type.Data)
		assert.Equal(t, "/var/log/auth.log", act.Data.Target.Data)
	})

	t.Run("a target that is not an action yields a null action", func(t *testing.T) {
		local7 := rules.Data[2].(*mqlRsyslogRule)
		assert.Equal(t, "foo bar", local7.Target.Data)
		act := local7.GetAction()
		require.NoError(t, act.Error)
		assert.Nil(t, act.Data)
		assert.True(t, act.IsNull())
	})

	t.Run("an imtcp input inherits the module's TLS settings from another file", func(t *testing.T) {
		inputs := conf.GetInputs()
		require.NoError(t, inputs.Error)
		require.Len(t, inputs.Data, 2)
		tcp := inputs.Data[0].(*mqlRsyslogInput)
		assert.Equal(t, "imtcp", tcp.Type.Data)
		assert.Equal(t, "1", tcp.StreamDriverMode.Data)
		assert.Equal(t, "x509/name", tcp.Parameters.Data.(map[string]any)["streamdriver.authmode"])
		udp := inputs.Data[1].(*mqlRsyslogInput)
		assert.Equal(t, "imudp", udp.Type.Data)
		assert.Empty(t, udp.StreamDriverMode.Data)
	})
}

// actionsByTarget indexes rsyslog.conf.actions by target.
func actionsByTarget(t *testing.T, conf *mqlRsyslogConf) map[string]*mqlRsyslogAction {
	t.Helper()
	actions := conf.GetActions()
	require.NoError(t, actions.Error)
	out := map[string]*mqlRsyslogAction{}
	for _, a := range actions.Data {
		act := a.(*mqlRsyslogAction)
		out[act.Target.Data] = act
	}
	return out
}

func TestRsyslogConf_IncludeOrderAndRulesets(t *testing.T) {
	conf := rsyslogFixtureConf(t, "testdata/rsyslog_rulesets.toml")
	byTarget := actionsByTarget(t, conf)

	t.Run("fragments are read in sorted order at the include", func(t *testing.T) {
		actions := conf.GetActions()
		require.NoError(t, actions.Error)
		var targets []string
		for _, a := range actions.Data {
			targets = append(targets, a.(*mqlRsyslogAction).Target.Data)
		}
		// The listing returns 60-receive.conf first; rsyslog sorts glob
		// matches, so 50-default.conf is read first. emerg.log follows the
		// include in rsyslog.conf.
		assert.Equal(t, []string{
			"/var/log/auth.log", "/var/log/syslog",
			"/var/log/remote.log", "central.example.com",
			"/var/log/emerg.log",
		}, targets)
	})

	t.Run("an included file takes the directives in effect at its include", func(t *testing.T) {
		auth := byTarget["/var/log/auth.log"]
		require.NotNil(t, auth)
		assert.Equal(t, "0640", auth.FileCreateMode.Data)
		assert.Equal(t, "syslog", auth.FileOwner.Data)
		assert.Equal(t, "adm", auth.FileGroup.Data)
		assert.Equal(t, "/etc/rsyslog.d/50-default.conf", auth.SourceFile.Data)

		emerg := byTarget["/var/log/emerg.log"]
		require.NotNil(t, emerg)
		assert.Equal(t, "0600", emerg.FileCreateMode.Data, "the directive after the include")
	})

	t.Run("a modern omfile action ignores $FileCreateMode", func(t *testing.T) {
		remote := byTarget["/var/log/remote.log"]
		require.NotNil(t, remote)
		assert.Equal(t, "0644", remote.FileCreateMode.Data)
		assert.Empty(t, remote.FileGroup.Data)
	})

	t.Run("the forward inside the ruleset", func(t *testing.T) {
		fwd := byTarget["central.example.com"]
		require.NotNil(t, fwd)
		assert.Equal(t, 6514, int(fwd.Port.Data))
		assert.True(t, fwd.IsRemote.Data)
		assert.True(t, fwd.TlsEnabled.Data)
		assert.Equal(t, "gtls", fwd.StreamDriver.Data)
		assert.Equal(t, "x509/name", fwd.StreamDriverAuthMode.Data)
		assert.Equal(t, "$fromhost-ip startswith '10.'", fwd.Condition.Data)
		assert.True(t, fwd.ResumeRetryCount.IsNull())
		assert.False(t, byTarget["/var/log/auth.log"].IsRemote.Data)
	})

	t.Run("action.rules is the reverse of rule.action", func(t *testing.T) {
		rules := byTarget["/var/log/syslog"].GetRules()
		require.NoError(t, rules.Error)
		require.Len(t, rules.Data, 2, "*.* and auth,authpriv.none")
		for _, r := range rules.Data {
			act := r.(*mqlRsyslogRule).GetAction()
			require.NoError(t, act.Error)
			assert.Same(t, byTarget["/var/log/syslog"], act.Data)
		}
		none := byTarget["/var/log/remote.log"].GetRules()
		require.NoError(t, none.Error)
		assert.Empty(t, none.Data)
	})

	rulesets := conf.GetRulesets()
	require.NoError(t, rulesets.Error)
	require.Len(t, rulesets.Data, 2)
	def := rulesets.Data[0].(*mqlRsyslogRuleset)
	remote := rulesets.Data[1].(*mqlRsyslogRuleset)
	assert.Equal(t, "RSYSLOG_DefaultRuleset", def.Name.Data)
	assert.Equal(t, "remote", remote.Name.Data)
	assert.Equal(t, "/etc/rsyslog.d/60-receive.conf", remote.SourceFile.Data)

	t.Run("a ruleset lists its actions and inputs", func(t *testing.T) {
		actions := remote.GetActions()
		require.NoError(t, actions.Error)
		var targets []string
		for _, a := range actions.Data {
			targets = append(targets, a.(*mqlRsyslogAction).Target.Data)
		}
		assert.Equal(t, []string{"/var/log/remote.log", "central.example.com"}, targets)

		inputs := remote.GetInputs()
		require.NoError(t, inputs.Error)
		require.Len(t, inputs.Data, 1)
		assert.Equal(t, int64(514), inputs.Data[0].(*mqlRsyslogInput).Port.Data)

		defInputs := def.GetInputs()
		require.NoError(t, defInputs.Error)
		require.Len(t, defInputs.Data, 2, "the dangling imudp binding and imuxsock")
		assert.Equal(t, "imudp", defInputs.Data[0].(*mqlRsyslogInput).Type.Data)
		assert.Equal(t, "imuxsock", defInputs.Data[1].(*mqlRsyslogInput).Type.Data)

		defActions := def.GetActions()
		require.NoError(t, defActions.Error)
		assert.Len(t, defActions.Data, 3, "auth.log, syslog, emerg.log")
	})

	t.Run("input.boundRuleset", func(t *testing.T) {
		inputs := conf.GetInputs()
		require.NoError(t, inputs.Error)
		require.Len(t, inputs.Data, 3)

		tcp := inputs.Data[0].(*mqlRsyslogInput).GetBoundRuleset()
		require.NoError(t, tcp.Error)
		assert.Same(t, remote, tcp.Data)

		// rsyslogd -N1: "ruleset 'missing' for *:514 not found - using
		// default ruleset instead".
		missing := inputs.Data[1].(*mqlRsyslogInput)
		assert.Equal(t, "missing", missing.Ruleset.Data)
		bound := missing.GetBoundRuleset()
		require.NoError(t, bound.Error)
		assert.Same(t, def, bound.Data)

		uxsock := inputs.Data[2].(*mqlRsyslogInput).GetBoundRuleset()
		require.NoError(t, uxsock.Error)
		assert.Same(t, def, uxsock.Data)
	})

	t.Run("globals merge the legacy and modern forms", func(t *testing.T) {
		globals := conf.GetGlobals()
		require.NoError(t, globals.Error)
		assert.Equal(t, map[string]any{
			"privdrop.user.name":     "syslog",
			"workdirectory":          "/var/spool/rsyslog",
			"defaultnetstreamdriver": "gtls",
		}, globals.Data)
	})
}

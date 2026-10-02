// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// parseAideString parses a single configuration with no includes.
func parseAideString(content string) *aideConfig {
	cfg := newAideConfig()
	parseAideConfig(cfg, "/etc/aide.conf", content, 0, nil)
	return cfg
}

const aideTestConfig = `# AIDE configuration
database_in=file:/var/lib/aide/aide.db.gz
database_out=file:/var/lib/aide/aide.db.new.gz
gzip_dbout=yes
report_url=file:/var/log/aide/aide.log

# attribute groups
NORMAL = R+sha512
STRONG = NORMAL-md5

@@define TOPDIR /var

/etc NORMAL
=/root STRONG
!/etc/mtab
@@{TOPDIR}/log R+sha256
/usr/bin f p+i+sha512   # trailing comment
`

func TestParseAideConfig(t *testing.T) {
	cfg := parseAideString(aideTestConfig)

	assert.Equal(t, map[string]string{
		"database_in":  "file:/var/lib/aide/aide.db.gz",
		"database_out": "file:/var/lib/aide/aide.db.new.gz",
		"gzip_dbout":   "yes",
		"report_url":   "file:/var/log/aide/aide.log",
	}, cfg.Params)

	// a key that is not a recognized option is a group definition
	assert.Equal(t, map[string]string{
		"NORMAL": "R+sha512",
		"STRONG": "NORMAL-md5",
	}, cfg.Groups)

	require.Len(t, cfg.Rules, 5)

	assert.Equal(t, "/etc", cfg.Rules[0].Path)
	assert.Equal(t, aideSelectionRecursive, cfg.Rules[0].Selection)
	assert.Equal(t, "NORMAL", cfg.Rules[0].Expression)
	// R has no definition in the configuration and the AIDE release is not
	// known, so it stays as written
	assert.Equal(t, []string{"R", "sha512"}, cfg.Rules[0].Attributes)

	assert.Equal(t, "/root", cfg.Rules[1].Path)
	assert.Equal(t, aideSelectionEquals, cfg.Rules[1].Selection)
	// STRONG resolves through NORMAL; "-md5" may remove a member of R, so it
	// is kept
	assert.Equal(t, []string{"-md5", "R", "sha512"}, cfg.Rules[1].Attributes)

	assert.Equal(t, "/etc/mtab", cfg.Rules[2].Path)
	assert.Equal(t, aideSelectionNegative, cfg.Rules[2].Selection)
	assert.Empty(t, cfg.Rules[2].Expression)
	assert.Empty(t, cfg.Rules[2].Attributes)

	// a macro reference opening the line is substituted, not read as a directive
	assert.Equal(t, "/var/log", cfg.Rules[3].Path)
	assert.Equal(t, []string{"R", "sha256"}, cfg.Rules[3].Attributes)

	// a trailing comment is not part of the expression
	assert.Equal(t, "/usr/bin", cfg.Rules[4].Path)
	assert.Equal(t, "f p+i+sha512", cfg.Rules[4].Expression)
	assert.Equal(t, []string{"f", "i", "p", "sha512"}, cfg.Rules[4].Attributes)

	assert.Equal(t, 13, cfg.Rules[0].LineNumber)
	assert.Equal(t, "/etc/aide.conf", cfg.Rules[0].File)
}

func TestParseAideConfig_GroupRemovalOfAGroup(t *testing.T) {
	cfg := parseAideString(`DIGESTS = sha256+sha512
BASE = p+i+DIGESTS
LOOSE = BASE-DIGESTS

/etc LOOSE
`)

	require.Len(t, cfg.Rules, 1)
	// removing a group removes every attribute it stands for
	assert.Equal(t, []string{"i", "p"}, cfg.Rules[0].Attributes)
}

func TestParseAideConfig_GroupCycleTerminates(t *testing.T) {
	cfg := parseAideString(`A = B+p
B = A+i

/etc A
`)

	require.Len(t, cfg.Rules, 1)
	assert.NotPanics(t, func() { _ = cfg.Rules[0].Attributes })
	assert.Subset(t, cfg.Rules[0].Attributes, []string{"i", "p"})
}

func TestParseAideConfig_Conditionals(t *testing.T) {
	cfg := parseAideString(`@@define WITH_SELINUX yes

@@ifdef WITH_SELINUX
/selinux R
@@else
/not-selinux R
@@endif

@@ifndef WITH_SELINUX
/absent R
@@endif

@@ifdef MISSING
/skipped R
@@else
/taken R
@@endif
`)

	paths := []string{}
	for _, rule := range cfg.Rules {
		paths = append(paths, rule.Path)
	}

	assert.Equal(t, []string{"/selinux", "/taken"}, paths)
}

func TestParseAideConfig_UndefinedMacroYieldsNoRule(t *testing.T) {
	cfg := parseAideString(`@@define TOPDIR /var
@@undef TOPDIR
@@{TOPDIR}/log R
/etc p
`)

	// the reference is left unexpanded, so the line names no absolute path and is
	// not a selection line; AIDE itself rejects the configuration in this state
	require.Len(t, cfg.Rules, 1)
	assert.Equal(t, "/etc", cfg.Rules[0].Path)
}

func TestParseAideConfig_UndefRemovesTheMacro(t *testing.T) {
	cfg := parseAideString(`@@define TOPDIR /var
@@{TOPDIR}/log R
@@undef TOPDIR
@@define TOPDIR /srv
@@{TOPDIR}/log R
`)

	require.Len(t, cfg.Rules, 2)
	assert.Equal(t, "/var/log", cfg.Rules[0].Path)
	assert.Equal(t, "/srv/log", cfg.Rules[1].Path)
}

func TestParseAideConfig_Includes(t *testing.T) {
	files := map[string][]aideIncludeFile{
		"/etc/aide/aide.conf.d": {
			{Path: "/etc/aide/aide.conf.d/10-base", Content: "EXTRA = p+i\n/opt EXTRA\n"},
			{Path: "/etc/aide/aide.conf.d/20-more", Content: "/srv EXTRA+sha512\n"},
		},
	}

	cfg := newAideConfig()
	parseAideConfig(cfg, "/etc/aide/aide.conf", `database_in=file:/var/lib/aide/aide.db
@@include /etc/aide/aide.conf.d
/etc p
`, 0, func(target string) []aideIncludeFile {
		return files[target]
	})

	require.Len(t, cfg.Rules, 3)

	// the include is folded in at the point it appears, so a group defined in
	// the first included file is visible to the second
	assert.Equal(t, "/opt", cfg.Rules[0].Path)
	assert.Equal(t, "/etc/aide/aide.conf.d/10-base", cfg.Rules[0].File)
	assert.Equal(t, "/srv", cfg.Rules[1].Path)
	assert.Equal(t, []string{"i", "p", "sha512"}, cfg.Rules[1].Attributes)

	// and the line after the include still belongs to the parent file
	assert.Equal(t, "/etc", cfg.Rules[2].Path)
	assert.Equal(t, "/etc/aide/aide.conf", cfg.Rules[2].File)
}

func TestParseAideConfig_IncludeInSkippedBranchIsNotRead(t *testing.T) {
	requested := []string{}

	cfg := newAideConfig()
	parseAideConfig(cfg, "/etc/aide.conf", `@@ifdef MISSING
@@include /etc/aide/never
@@endif
`, 0, func(target string) []aideIncludeFile {
		requested = append(requested, target)
		return nil
	})

	assert.Empty(t, requested)
	assert.Empty(t, cfg.Rules)
}

func TestParseAideConfig_IncludeDepthIsBounded(t *testing.T) {
	// a file including itself must not recurse without end
	calls := 0

	cfg := newAideConfig()
	parseAideConfig(cfg, "/etc/aide.conf", "@@include /etc/aide.conf\n", 0, func(target string) []aideIncludeFile {
		calls++
		return []aideIncludeFile{{Path: target, Content: "@@include /etc/aide.conf\n"}}
	})

	assert.LessOrEqual(t, calls, aideMaxIncludeDepth+1)
}

func TestParseAideConfig_XIncludeTakesOnlyThePath(t *testing.T) {
	requested := []string{}

	cfg := newAideConfig()
	parseAideConfig(cfg, "/etc/aide.conf", "@@x_include /etc/aide/conf.d ^[a-z]+$\n", 0, func(target string) []aideIncludeFile {
		requested = append(requested, target)
		return nil
	})

	// the regular expression trailing the path is not part of it
	assert.Equal(t, []string{"/etc/aide/conf.d"}, requested)
}

func TestStripAideComment(t *testing.T) {
	tests := []struct {
		title    string
		line     string
		expected string
	}{
		{"no comment", "/etc NORMAL", "/etc NORMAL"},
		{"trailing comment", "/etc NORMAL # watch etc", "/etc NORMAL "},
		{"whole line", "# just a comment", ""},
		{"escaped hash is kept", `/etc/we\#ird NORMAL`, `/etc/we\#ird NORMAL`},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			assert.Equal(t, test.expected, stripAideComment(test.line))
		})
	}
}

func TestAideDatabasePath(t *testing.T) {
	tests := []struct {
		title    string
		value    string
		expected string
	}{
		{"file prefix", "file:/var/lib/aide/aide.db.gz", "/var/lib/aide/aide.db.gz"},
		{"file url", "file:///var/lib/aide/aide.db", "/var/lib/aide/aide.db"},
		{"bare path", "/var/lib/aide/aide.db", "/var/lib/aide/aide.db"},
		{"stdout names no file", "stdout", ""},
		{"fd names no file", "fd:3", ""},
		{"empty", "", ""},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			assert.Equal(t, test.expected, aideDatabasePath(test.value))
		})
	}
}

func TestParseAideVersion(t *testing.T) {
	tests := []struct {
		title    string
		out      string
		expected string
	}{
		{"aide 0.17", "Aide 0.17.4\n\nCompiled with...\n", "0.17.4"},
		{"aide 0.18", "Aide 0.18.6", "0.18.6"},
		{"leading blank line", "\nAide 0.16\n", "0.16"},
		{"no version", "command not found\n", ""},
		{"empty", "", ""},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			assert.Equal(t, test.expected, parseAideVersion(test.out))
		})
	}
}

func TestSplitAideExpression(t *testing.T) {
	tokens := splitAideExpression("p+i-md5+sha512")

	assert.Equal(t, []aideExpressionToken{
		{name: "p", remove: false},
		{name: "i", remove: false},
		{name: "md5", remove: true},
		{name: "sha512", remove: false},
	}, tokens)
}

func readAideTestdata(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/aide/" + name)
	require.NoError(t, err)
	return string(data)
}

func TestAideBuiltinGroups(t *testing.T) {
	// AIDE 0.19.2 on RHEL 9 lists its groups in --version
	groups := aideBuiltinGroups(readAideTestdata(t, "version-0.19.2.txt"))
	assert.Equal(t, map[string]string{
		"R": "l+p+u+g+s+c+m+i+n+acl+selinux+xattrs+ftype+e2fsattrs+sha3_256",
		"L": "l+p+u+g+i+n+acl+selinux+xattrs+ftype+e2fsattrs",
		">": "l+p+u+g+s+i+n+acl+selinux+xattrs+ftype+e2fsattrs+growing",
		"H": "sha256+sha512+stribog256+stribog512+sha512_256+sha3_256+sha3_512",
		"X": "acl+selinux+xattrs+e2fsattrs",
		"E": "",
	}, groups)

	// 0.15.1 (RHEL 7) and 0.16 (RHEL 8) do not list them. An `aide --init`
	// with a rule of just R stored perm, ftype, inode, lcount, uid, gid, size,
	// mtime, ctime, md5, acl, selinux, xattrs and e2fsattrs on both.
	r := []string{"acl", "c", "e2fsattrs", "ftype", "g", "i", "l", "m", "md5", "n", "p", "s", "selinux", "u", "xattrs"}
	l := []string{"acl", "e2fsattrs", "ftype", "g", "i", "l", "n", "p", "selinux", "u", "xattrs"}
	for _, file := range []string{"version-0.15.1.txt", "version-0.16.txt"} {
		cfg := newAideConfig()
		cfg.Builtins = aideBuiltinGroups(readAideTestdata(t, file))
		require.NotNil(t, cfg.Builtins, file)
		assert.Equal(t, r, resolveAideAttributes(cfg, "R"), file)
		assert.Equal(t, l, resolveAideAttributes(cfg, "L"), file)
		assert.Empty(t, resolveAideAttributes(cfg, "E"), file)
	}
	// X is a group from 0.16 on
	assert.NotContains(t, aideBuiltinGroups(readAideTestdata(t, "version-0.15.1.txt")), "X")
	assert.Equal(t, "acl+selinux+xattrs+e2fsattrs", aideBuiltinGroups(readAideTestdata(t, "version-0.16.txt"))["X"])

	// a 0.16 built without ACL, xattr or a hash library leaves those out
	assert.Equal(t, "p+ftype+i+n+u+g+s+l+m+c+selinux",
		aideBuiltinGroups("Aide 0.16\n\nCompiled with the following options:\n\nWITH_MMAP\nWITH_SELINUX\n")["R"])

	assert.Nil(t, aideBuiltinGroups(""))
	assert.Nil(t, aideBuiltinGroups("sh: aide: command not found"))
	// a release without a group listing that is not 0.15 or 0.16 is not guessed
	assert.Nil(t, aideBuiltinGroups("Aide 0.14.2\n"))
}

// The rules of RHEL 9's aide.conf resolve to the attributes AIDE 0.19.2 itself
// reports for them (`aide --config-check -L rule`), including NORMAL, which
// is R+sha512-m-c.
func TestParseAideConfig_MatchesAideRuleTree(t *testing.T) {
	cfg := newAideConfig()
	cfg.Builtins = aideBuiltinGroups(readAideTestdata(t, "version-0.19.2.txt"))
	parseAideConfig(cfg, "/etc/aide.conf", readAideTestdata(t, "rhel9-aide.conf"), 0, nil)

	byLine := map[int][]string{}
	for _, rule := range cfg.Rules {
		byLine[rule.LineNumber] = rule.Attributes
	}

	// a negative rule carries no attributes: '!/etc/mtab (none)'
	ruleLine := regexp.MustCompile(`'(\S+) \S+(?: ([^' ]*))?' \(/etc/aide\.conf:(\d+):`)
	checked := 0
	for _, line := range strings.Split(readAideTestdata(t, "rhel9-aide-config-check-rules.txt"), "\n") {
		m := ruleLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		lineNumber, err := strconv.Atoi(m[3])
		require.NoError(t, err)
		want := []string{}
		if m[2] != "" {
			want = strings.Split(m[2], "+")
		}
		sort.Strings(want)
		got, ok := byLine[lineNumber]
		require.True(t, ok, "aide reports a rule on line %d (%s) the parser did not find", lineNumber, m[1])
		assert.Equal(t, want, got, "line %d %s", lineNumber, m[1])
		checked++
	}
	assert.Equal(t, len(cfg.Rules), checked, "every parsed rule is one AIDE reports")
	assert.Greater(t, checked, 100)
}

func TestParseAideConfig_UnknownReleaseKeepsRemovals(t *testing.T) {
	// without the release, R cannot be expanded; its removals stay visible
	cfg := parseAideString("NORMAL = R+sha512-m-c\nCONTENT = sha512+ftype-ftype\n/etc NORMAL\n/opt CONTENT\n")
	require.Len(t, cfg.Rules, 2)
	assert.Equal(t, []string{"-c", "-m", "R", "sha512"}, cfg.Rules[0].Attributes)
	// a removal of something the expression holds is applied, not kept
	assert.Equal(t, []string{"sha512"}, cfg.Rules[1].Attributes)
}

func TestParseAideConfig_RecentOptionsAreParams(t *testing.T) {
	cfg := parseAideString(readAideTestdata(t, "rhel9-aide.conf"))
	assert.Equal(t, "plain", cfg.Params["report_format"])
	assert.Equal(t, "false", cfg.Params["config_check_warn_unrestricted_rules"])
	assert.NotContains(t, cfg.Groups, "report_format")
	assert.NotContains(t, cfg.Groups, "config_check_warn_unrestricted_rules")
	assert.Equal(t, "R+sha512-m-c", cfg.Groups["NORMAL"])
}

func TestAideConfigReadError(t *testing.T) {
	denied := &fs.PathError{Op: "open", Path: "/etc/aide.conf", Err: os.ErrPermission}

	withStructuredErrors(t, true)
	err := aideConfigReadError("/etc/aide.conf", denied)
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrForbidden), "a refused read is forbidden: %v", err)
	assert.Contains(t, err.Error(), "/etc/aide.conf")
	assert.NoError(t, aideConfigReadError("/etc/aide.conf", nil))

	// v13: the unreadable file is skipped
	withStructuredErrors(t, false)
	assert.NoError(t, aideConfigReadError("/etc/aide.conf", denied))
}

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

	"github.com/spf13/afero"
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
!/var/run d
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

	require.Len(t, cfg.Rules, 6)

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

	// a trailing comment is not part of the expression, and the file type
	// restriction between the path and the attributes is not an attribute
	assert.Equal(t, "/usr/bin", cfg.Rules[4].Path)
	assert.Equal(t, "f", cfg.Rules[4].Restriction)
	assert.Equal(t, "p+i+sha512", cfg.Rules[4].Expression)
	assert.Equal(t, []string{"i", "p", "sha512"}, cfg.Rules[4].Attributes)
	assert.Empty(t, cfg.Rules[0].Restriction)

	// a negative rule takes a restriction and no attributes
	assert.Equal(t, "/var/run", cfg.Rules[5].Path)
	assert.Equal(t, aideSelectionNegative, cfg.Rules[5].Selection)
	assert.Equal(t, "d", cfg.Rules[5].Restriction)
	assert.Empty(t, cfg.Rules[5].Expression)
	assert.Empty(t, cfg.Rules[5].Attributes)

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

func TestParseAideConfig_UndefinedMacroIsEmpty(t *testing.T) {
	// Debian 13's 31_aide_bind9 on a host without a bind chroot: AIDE 0.19.1
	// reports '/run/named$ d ...' for line 6
	cfg := parseAideString(`@@define RUN run
/@@{BINDCHROOT}@@{RUN}/named$ d p
@@define TOPDIR /var
@@undef TOPDIR
@@{TOPDIR}/log R
`)

	require.Len(t, cfg.Rules, 2)
	assert.Equal(t, "/run/named$", cfg.Rules[0].Path)
	assert.Equal(t, "/log", cfg.Rules[1].Path)
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
`, 0, func(include aideInclude) []aideIncludeFile {
		return files[include.Target]
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
`, 0, func(include aideInclude) []aideIncludeFile {
		requested = append(requested, include.Target)
		return nil
	})

	assert.Empty(t, requested)
	assert.Empty(t, cfg.Rules)
}

func TestParseAideConfig_IncludeDepthIsBounded(t *testing.T) {
	// a file including itself must not recurse without end
	calls := 0

	cfg := newAideConfig()
	parseAideConfig(cfg, "/etc/aide.conf", "@@include /etc/aide.conf\n", 0, func(include aideInclude) []aideIncludeFile {
		calls++
		return []aideIncludeFile{{Path: include.Target, Content: "@@include /etc/aide.conf\n"}}
	})

	assert.LessOrEqual(t, calls, aideMaxIncludeDepth+1)
}

func TestParseAideConfig_XInclude(t *testing.T) {
	requested := []aideInclude{}

	// Debian 13's aide.conf
	cfg := newAideConfig()
	parseAideConfig(cfg, "/etc/aide.conf", `@@x_include_setenv UPAC_settingsd /etc/aide/aide.settings.d
@@x_include_setenv PATH /bin:/usr/bin
@@x_include /etc/aide/aide.conf.d ^[a-zA-Z0-9_-]+$
@@include /etc/aide/plain.d ^[a-z]+$ /mnt/root
`, 0, func(include aideInclude) []aideIncludeFile {
		requested = append(requested, include)
		if include.Target == "/etc/aide/plain.d" {
			return []aideIncludeFile{{Path: "/etc/aide/plain.d/a", Content: "/etc p\n"}}
		}
		return nil
	})

	env := []aideEnvVar{{Name: "UPAC_settingsd", Value: "/etc/aide/aide.settings.d"}, {Name: "PATH", Value: "/bin:/usr/bin"}}
	assert.Equal(t, []aideInclude{
		// the regular expression trailing the path is not part of it
		{Target: "/etc/aide/aide.conf.d", Regex: "^[a-zA-Z0-9_-]+$", Execute: true, Env: env},
		{Target: "/etc/aide/plain.d", Regex: "^[a-z]+$"},
	}, requested)

	// a RULE_PREFIX (AIDE 0.18+) is prepended to the included rules
	require.Len(t, cfg.Rules, 1)
	assert.Equal(t, "/mnt/root/etc", cfg.Rules[0].Path)
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
		{"aide 0.18 lowercase", "aide 0.18.6\n", "0.18.6"},
		// what `aide --version` prints through sh -c when aide is not on PATH
		{"bash command not found", "bash: line 1: aide: command not found\n", ""},
		{"dash not found", "sh: 1: aide: not found\n", ""},
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

func TestParseAideConfig_If(t *testing.T) {
	// appended to the stock aide.conf on Debian 11, 12 and 13, AIDE 0.17.3 to
	// 0.19.1 report no rule for /g05cond
	cfg := parseAideString("@@if defined G05_NEVER\n/g05cond p+sha256\n@@endif\n")
	assert.Empty(t, cfg.Rules)

	// Debian's 10_aide_constants: a fallback defined when nothing else did
	cfg = parseAideString(`@@if not defined RUN
@@define RUN run
@@endif
@@define LOCK lock
@@if not defined LOCK
@@define LOCK never
@@endif
/@@{RUN}/@@{LOCK}$ d p
`)
	require.Len(t, cfg.Rules, 1)
	assert.Equal(t, "/run/lock$", cfg.Rules[0].Path)
}

func TestParseAideConfig_IfInsideIfdef(t *testing.T) {
	// the @@endif closing the inner @@if must not end the outer block
	cfg := parseAideString(`@@ifdef MISSING
@@if not defined OTHER
/inner p
@@endif
/outer p
@@define LEAKED 1
@@endif
@@ifdef LEAKED
/leaked p
@@endif
/after p
`)

	paths := []string{}
	for _, rule := range cfg.Rules {
		paths = append(paths, rule.Path)
	}
	assert.Equal(t, []string{"/after"}, paths)
	assert.NotContains(t, cfg.Macros, "LEAKED")
}

func TestParseAideConfig_UndecidableIfReadsBothBranches(t *testing.T) {
	cfg := parseAideString(`@@if hostname web01
/web p
@@else
/other p
@@endif
@@if frobnicate something
/unknown p
@@endif
`)

	paths := []string{}
	for _, rule := range cfg.Rules {
		paths = append(paths, rule.Path)
	}
	assert.Equal(t, []string{"/web", "/other", "/unknown"}, paths)
}

func TestEvalAideCondition(t *testing.T) {
	cfg := newAideConfig()
	cfg.Version = "0.19.1"
	cfg.Host = aideHost{
		Hostname: "web01",
		Exists: func(p string) (bool, bool) {
			switch p {
			case "/var/log/journal":
				return true, true
			case "/usr/share/doc/tor/copyright":
				return false, true
			}
			return false, false
		},
	}
	cfg.defineBuiltinMacros()
	cfg.Macros["RUN"] = "run"

	tests := []struct {
		expression string
		expected   aideBranch
	}{
		{"defined RUN", aideBranchKeep},
		{"defined MISSING", aideBranchSkip},
		{"not defined MISSING", aideBranchKeep},
		{"not not defined RUN", aideBranchKeep},
		// AIDE defines both itself
		{"defined HOSTNAME", aideBranchKeep},
		{"defined AIDE_VERSION", aideBranchKeep},
		{"hostname web01", aideBranchKeep},
		{"hostname db01", aideBranchSkip},
		{"not hostname db01", aideBranchKeep},
		{"exists /var/log/journal", aideBranchKeep},
		{"exists /usr/share/doc/tor/copyright", aideBranchSkip},
		{"exists /unreadable", aideBranchUnknown},
		{"not exists /unreadable", aideBranchUnknown},
		{"@@{AIDE_VERSION} version_ge 0.19", aideBranchKeep},
		{"@@{AIDE_VERSION} version_ge 0.19.2", aideBranchSkip},
		{"0.19.1 version_ge 0.18", aideBranchKeep},
		{"1.1 version_ge 2.17", aideBranchSkip},
		{"0.20-rc1 version_ge 0.20", aideBranchKeep},
		{"defined", aideBranchUnknown},
		{"frobnicate X", aideBranchUnknown},
	}
	for _, test := range tests {
		t.Run(test.expression, func(t *testing.T) {
			assert.Equal(t, test.expected, evalAideCondition(cfg, test.expression))
		})
	}

	// nothing known about the host or the release
	unknown := newAideConfig()
	assert.Equal(t, aideBranchUnknown, evalAideCondition(unknown, "hostname web01"))
	assert.Equal(t, aideBranchUnknown, evalAideCondition(unknown, "exists /var/log/journal"))
	assert.Equal(t, aideBranchUnknown, evalAideCondition(unknown, "defined HOSTNAME"))
	assert.Equal(t, aideBranchUnknown, evalAideCondition(unknown, "defined AIDE_VERSION"))
	assert.Equal(t, aideBranchUnknown, evalAideCondition(unknown, "@@{AIDE_VERSION} version_ge 0.18"))

	// AIDE_VERSION is defined from 0.19 on
	old := newAideConfig()
	old.Version = "0.18.3"
	old.defineBuiltinMacros()
	assert.Equal(t, aideBranchSkip, evalAideCondition(old, "defined AIDE_VERSION"))
}

func TestParseAideConfig_NonRecursiveNegativeRule(t *testing.T) {
	// appended to Debian 13's aide.conf, AIDE 0.19.1 reports '-/etc$ (none)'
	cfg := parseAideString("-/etc$ 0\n-/dev =tmpfs\n")

	require.Len(t, cfg.Rules, 2)
	assert.Equal(t, "/etc$", cfg.Rules[0].Path)
	assert.Equal(t, aideSelectionNonRecursiveNegative, cfg.Rules[0].Selection)
	assert.Empty(t, cfg.Rules[0].Restriction)
	assert.Empty(t, cfg.Rules[0].Attributes)

	assert.Equal(t, "/dev", cfg.Rules[1].Path)
	assert.Equal(t, "=tmpfs", cfg.Rules[1].Restriction)
}

func TestParseAideConfig_RestrictedRules(t *testing.T) {
	// AIDE 0.17.3 to 0.19.1 report '/g05r f p+sha256' and '!/g05n d'
	cfg := parseAideString("/g05r f p+sha256\n!/g05n d\n=/boot/efi$ d=vfat R\n/ 0 p\n")

	require.Len(t, cfg.Rules, 4)
	assert.Equal(t, "f", cfg.Rules[0].Restriction)
	assert.Equal(t, "p+sha256", cfg.Rules[0].Expression)
	assert.Equal(t, []string{"p", "sha256"}, cfg.Rules[0].Attributes)

	assert.Equal(t, aideSelectionNegative, cfg.Rules[1].Selection)
	assert.Equal(t, "d", cfg.Rules[1].Restriction)
	assert.Empty(t, cfg.Rules[1].Attributes)

	assert.Equal(t, aideSelectionEquals, cfg.Rules[2].Selection)
	assert.Equal(t, "d=vfat", cfg.Rules[2].Restriction)
	assert.Equal(t, []string{"R"}, cfg.Rules[2].Attributes)

	// 0 is the explicitly empty restriction (0.18+)
	assert.Empty(t, cfg.Rules[3].Restriction)
	assert.Equal(t, []string{"p"}, cfg.Rules[3].Attributes)
}

func TestParseAideConfig_Escapes(t *testing.T) {
	// Debian 12's 31_aide_grub-efi and 31_aide_udev; AIDE 0.18.3 reports the
	// paths '/boot/efi/EFI/BOOT/BOOTX64\.EFI$' and
	// '/run/udev/data/\+drivers:[-[:lower:][:digit:]_]+:[-[:alnum:] _]+$'
	content := `/boot/efi/EFI/BOOT/BOOTX64\\.EFI$ f p
!/run/udev/data/\\+drivers:[-[:lower:][:digit:]_]+:[-[:alnum:]\ _]+$ f
/srv/a\@b p
`
	cfg := parseAideString(content)
	require.Len(t, cfg.Rules, 3)
	assert.Equal(t, `/boot/efi/EFI/BOOT/BOOTX64\.EFI$`, cfg.Rules[0].Path)
	assert.Equal(t, "f", cfg.Rules[0].Restriction)
	// an escaped space does not end the path
	assert.Equal(t, `/run/udev/data/\+drivers:[-[:lower:][:digit:]_]+:[-[:alnum:] _]+$`, cfg.Rules[1].Path)
	assert.Equal(t, "f", cfg.Rules[1].Restriction)
	assert.Equal(t, "/srv/a@b", cfg.Rules[2].Path)

	// AIDE 0.16 does not read these escapes
	cfg = newAideConfig()
	cfg.Version = "0.16.1"
	parseAideConfig(cfg, "/etc/aide.conf", content, 0, nil)
	require.Len(t, cfg.Rules, 3)
	assert.Equal(t, `/boot/efi/EFI/BOOT/BOOTX64\\.EFI$`, cfg.Rules[0].Path)
}

func TestCompareAideVersions(t *testing.T) {
	tests := []struct {
		a, b     string
		expected int
		ok       bool
	}{
		{"0.19.1", "0.18", 1, true},
		{"0.18", "0.18.0", 0, true},
		{"0.17.3", "0.17.4", -1, true},
		{"1.0", "0.19.2", 1, true},
		{"0.19.1-rc2", "0.19.1", 0, true},
		{"", "0.18", 0, false},
		{"abc", "0.18", 0, false},
	}
	for _, test := range tests {
		cmp, ok := compareAideVersions(test.a, test.b)
		assert.Equal(t, test.ok, ok, "%s vs %s", test.a, test.b)
		assert.Equal(t, test.expected, cmp, "%s vs %s", test.a, test.b)
	}
}

func TestAideIncludeEntries(t *testing.T) {
	names := []string{"31_aide_sudo", "10_aide_run", "31_aide_sudo.dpkg-old", "README.md", "70_aide_etc"}

	// Debian's file name restriction drops package-manager leftovers
	assert.Equal(t, []string{"10_aide_run", "31_aide_sudo", "70_aide_etc"}, aideIncludeEntries(names, "^[a-zA-Z0-9_-]+$"))
	// without one, every file is read, in lexical order
	assert.Equal(t, []string{"10_aide_run", "31_aide_sudo", "31_aide_sudo.dpkg-old", "70_aide_etc", "README.md"}, aideIncludeEntries(names, ""))
	assert.Empty(t, aideIncludeEntries(names, "("))
}

func TestAideConfigHasInclude(t *testing.T) {
	assert.True(t, aideConfigHasInclude(readAideTestdata(t, "debian13/aide.conf")))
	assert.True(t, aideConfigHasInclude("@@include /etc/aide.d\n"))
	assert.False(t, aideConfigHasInclude(readAideTestdata(t, "rhel9-aide.conf")))
	// Debian 10's aide.conf: settings and groups, the rules come from
	// update-aide.conf
	assert.False(t, aideConfigHasInclude("database=file:/var/lib/aide/aide.db\n# @@x_include in a comment\n@@x_include_setenv PATH /bin\nVarFile = OwnerMode+n+l+X\n"))
}

func TestAideScriptCommand(t *testing.T) {
	assert.Equal(t,
		`sh -c '[ -n "${UPAC_settingsd+x}" ] || export UPAC_settingsd=/etc/aide/aide.settings.d; [ -n "${PATH+x}" ] || export PATH=/bin:/usr/bin; exec /etc/aide/aide.conf.d/10_aide_hostname'`,
		aideScriptCommand("/etc/aide/aide.conf.d/10_aide_hostname", []aideEnvVar{
			{Name: "UPAC_settingsd", Value: "/etc/aide/aide.settings.d"},
			{Name: "PATH", Value: "/bin:/usr/bin"},
			{Name: "BAD NAME", Value: "x"},
		}))
}

// The stock Debian 13 configuration (aide.conf, a selection of aide.conf.d,
// and the output of its executable files) resolves to the rules AIDE 0.19.1
// itself reports (`aide --config-check -L rule`), with path, selection,
// restriction and attributes. It holds 61 @@if blocks, many over macros that
// executable files define, rules restricted to file types, and escaped paths.
func TestParseAideConfig_MatchesDebian13RuleTree(t *testing.T) {
	const fixture = "testdata/aide/debian13"

	cfg := newAideConfig()
	version := readAideTestdata(t, "debian13/version.txt")
	cfg.Builtins = aideBuiltinGroups(version)
	cfg.Version = parseAideVersion(version)
	cfg.Host = aideHost{
		Hostname: "deb13-host",
		Exists: func(p string) (bool, bool) {
			return p == "/var/log/journal", true
		},
	}
	cfg.defineBuiltinMacros()
	require.Equal(t, "0.19.1", cfg.Version)

	resolve := func(include aideInclude) []aideIncludeFile {
		require.Equal(t, "/etc/aide/aide.conf.d", include.Target)
		names := []string{}
		for _, dir := range []string{"aide.conf.d", "x"} {
			entries, err := os.ReadDir(fixture + "/" + dir)
			require.NoError(t, err)
			for _, entry := range entries {
				names = append(names, entry.Name())
			}
		}
		res := []aideIncludeFile{}
		for _, name := range aideIncludeEntries(names, include.Regex) {
			// x holds what the executable files print
			content, err := os.ReadFile(fixture + "/x/" + name)
			if err != nil {
				content, err = os.ReadFile(fixture + "/aide.conf.d/" + name)
			}
			require.NoError(t, err)
			res = append(res, aideIncludeFile{Path: include.Target + "/" + name, Content: string(content)})
		}
		return res
	}
	parseAideConfig(cfg, "/etc/aide/aide.conf", readAideTestdata(t, "debian13/aide.conf"), 0, resolve)

	type location struct {
		file string
		line int
	}
	parsed := map[location]aideSelectionRule{}
	for _, rule := range cfg.Rules {
		parsed[location{rule.File, rule.LineNumber}] = rule
	}

	// '<path> <restriction> <attributes>' for a rule, '!<path> <restriction>'
	// for a negative one; a path may hold a space
	positive := regexp.MustCompile(`^'(=?)(/.*) (\S+) ([^' ]*)' \((\S+?)(?: \(stdout\))?:(\d+): `)
	negative := regexp.MustCompile(`^'([!-])(/.*) (\S+)()' \((\S+?)(?: \(stdout\))?:(\d+): `)
	selections := map[string]string{
		"":  aideSelectionRecursive,
		"=": aideSelectionEquals,
		"!": aideSelectionNegative,
		"-": aideSelectionNonRecursiveNegative,
	}

	checked := 0
	for _, line := range strings.Split(readAideTestdata(t, "debian13/config-check-rules.txt"), "\n") {
		m := negative.FindStringSubmatch(line)
		if m == nil {
			m = positive.FindStringSubmatch(line)
		}
		if m == nil {
			continue
		}
		lineNumber, err := strconv.Atoi(m[6])
		require.NoError(t, err)
		rule, ok := parsed[location{m[5], lineNumber}]
		require.True(t, ok, "aide reports a rule at %s:%d (%s) the parser did not find", m[5], lineNumber, m[2])

		restriction := m[3]
		if restriction == "(none)" {
			restriction = ""
		}
		want := []string{}
		if m[4] != "" {
			want = strings.Split(m[4], "+")
		}
		sort.Strings(want)

		where := m[5] + ":" + m[6]
		assert.Equal(t, selections[m[1]], rule.Selection, where)
		assert.Equal(t, m[2], rule.Path, where)
		assert.Equal(t, restriction, rule.Restriction, where)
		assert.Equal(t, want, rule.Attributes, where)
		checked++
	}
	assert.Equal(t, len(cfg.Rules), checked, "every parsed rule is one AIDE reports")
	assert.Greater(t, checked, 180)
}

// AIDE before 0.19 has no '-' rules: 0.18.6 (Ubuntu 24.04) refuses the whole
// configuration with "unexpected character: '-'", so it checks nothing.
func TestParseAideConfig_NonRecursiveNegativeRuleBefore019(t *testing.T) {
	for _, version := range []string{"0.18.6", "0.17.3", "0.16"} {
		t.Run(version, func(t *testing.T) {
			cfg := newAideConfig()
			cfg.Version = version
			parseAideConfig(cfg, "/etc/aide/aide.conf", "/etc p+sha256\n-/etc$ 0\n", 0, nil)

			require.Error(t, cfg.Invalid)
			assert.Contains(t, cfg.Invalid.Error(), "/etc/aide/aide.conf:2")
			assert.Contains(t, cfg.Invalid.Error(), "AIDE "+version)
			for _, rule := range cfg.Rules {
				assert.NotEqual(t, aideSelectionNonRecursiveNegative, rule.Selection)
			}
		})
	}

	t.Run("0.19.1 reads it", func(t *testing.T) {
		cfg := newAideConfig()
		cfg.Version = "0.19.1"
		parseAideConfig(cfg, "/etc/aide/aide.conf", "-/etc$ 0\n", 0, nil)
		assert.NoError(t, cfg.Invalid)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, aideSelectionNonRecursiveNegative, cfg.Rules[0].Selection)
	})

	t.Run("unknown release reads it", func(t *testing.T) {
		cfg := parseAideString("-/etc$ 0\n")
		assert.NoError(t, cfg.Invalid)
		require.Len(t, cfg.Rules, 1)
	})
}

func TestAideVersionCommandMissing(t *testing.T) {
	assert.True(t, aideCommandMissing(127, ""))
	// sudo without the binary on secure_path exits 1
	assert.True(t, aideCommandMissing(1, "sudo: aide: command not found\n"))
	assert.True(t, aideCommandMissing(1, "bash: line 1: aide: command not found\n"))
	assert.False(t, aideCommandMissing(0, "Aide 0.16\n"))
	// some releases print the version and exit non-zero
	assert.False(t, aideCommandMissing(1, "Aide 0.15.1\n"))
}

// Removing the aide package on Debian (`apt remove`) leaves its conffiles,
// /etc/aide/aide.conf among them, but takes the binary: AIDE is not installed.
func TestAideBinaryPath(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/aide/aide.conf", []byte("/etc p\n"), 0o644))
	assert.Equal(t, "", aideBinaryPath(fs))

	require.NoError(t, afero.WriteFile(fs, "/usr/bin/aide", []byte{}, 0o755))
	assert.Equal(t, "/usr/bin/aide", aideBinaryPath(fs))

	rhel := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(rhel, "/usr/sbin/aide", []byte{}, 0o700))
	assert.Equal(t, "/usr/sbin/aide", aideBinaryPath(rhel))
}

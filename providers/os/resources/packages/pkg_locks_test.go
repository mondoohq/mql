// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	iofs "io/fs"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestIsHeldStatus(t *testing.T) {
	tests := []struct {
		status string
		held   bool
		why    string
	}{
		{"hold ok installed", true, "dpkg records the hold in the want field, which is what apt-mark hold writes"},
		{"install hold installed", true, "opkg records it in the flag field, where dpkg carried it historically"},
		{"install ok installed", false, "the ordinary installed package"},
		{"deinstall ok config-files", false, "removed but configured"},
		{"", false, "no status at all"},
		{"install ok not-installed", false, ""},
		// The reason this reads two fields rather than searching the string:
		// a package may be called anything.
		{"install ok installed hold-foo", false, "a token after the triple is not a hold"},
	}

	for _, test := range tests {
		t.Run(test.status, func(t *testing.T) {
			assert.Equal(t, test.held, isHeldStatus(test.status), test.why)
		})
	}
}

// The entry formats below were read off real hosts, not written by hand: the
// dnf4 one from AlmaLinux 9, the yum one from Amazon Linux 2. They put the
// epoch in different places, which is the detail documentation does not warn
// about.
func TestVersionlockEntryName(t *testing.T) {
	tests := []struct {
		entry string
		name  string
		why   string
	}{
		{"vim-minimal-2:8.2.2637-26.el9_8.4.*", "vim-minimal", "dnf4: epoch sits after the name"},
		{"2:vim-minimal-9.0.2153-1.amzn2.0.9.*", "vim-minimal", "yum: epoch prefixes the whole entry"},
		{"kernel-0:5.14.0-284.el9.x86_64", "kernel", ""},
		// A name containing a hyphen must not be cut at the first one.
		{"python3-dnf-plugin-versionlock-4.3.0-1.el9.noarch", "python3-dnf-plugin-versionlock", ""},
		// The case that rules out a left-to-right scan: this name itself
		// begins with a hyphen followed by a digit.
		{"java-1.8.0-openjdk-1:1.8.0.442.b06-2.el9.x86_64", "java-1.8.0-openjdk", "a name that contains a version-looking part"},
		{"kernel*", "kernel*", "a bare glob names no version and is kept whole"},
		{"nginx", "nginx", "a bare name"},
	}

	for _, test := range tests {
		t.Run(test.entry, func(t *testing.T) {
			assert.Equal(t, test.name, versionlockEntryName(test.entry), test.why)
		})
	}
}

func TestParseVersionlockListFixtures(t *testing.T) {
	for _, tc := range []struct{ fixture, why string }{
		{"versionlock_dnf4.list", "written by dnf versionlock add on almalinux:9"},
		{"versionlock_yum.list", "written by yum versionlock add on amazonlinux:2"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/" + tc.fixture)
			require.NoError(t, err)

			locks := parseVersionlockList(string(raw))
			assert.True(t, locks.has("vim-minimal"), tc.why)
			// The comment line and the leading blank line are not entries.
			assert.Len(t, locks, 1)
			// A different package on the same host is not locked.
			assert.False(t, locks.has("vim"), "a prefix of a locked name is a different package")
			assert.False(t, locks.has("bash"))
		})
	}
}

func TestParseVersionlockTOMLFixture(t *testing.T) {
	// dnf5 changed the format, not just the path.
	raw, err := os.ReadFile("testdata/versionlock_dnf5.toml")
	require.NoError(t, err)

	locks := parseVersionlockTOML(raw)
	assert.True(t, locks.has("vim-minimal"), "written by dnf versionlock add on fedora:latest")
	assert.Len(t, locks, 1)
	assert.False(t, locks.has("vim"))
}

func TestParseZypperLocksFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/zypp_locks")
	require.NoError(t, err)

	locks := parseZypperLocks(string(raw))
	assert.True(t, locks.has("vim"), "written by zypper al on opensuse/leap:15")
	assert.Len(t, locks, 1)
}

// A lock on something that is not a package does not hold an installed package
// at its version, so it must not mark one pinned.
func TestParseZypperLocksSkipsNonPackageLocks(t *testing.T) {
	locks := parseZypperLocks(`type: package
match_type: glob
case_sensitive: on
solvable_name: vim

type: pattern
match_type: glob
case_sensitive: on
solvable_name: devel_basis
`)
	assert.True(t, locks.has("vim"))
	assert.False(t, locks.has("devel_basis"), "a pattern lock is not a package lock")
	assert.Len(t, locks, 1)
}

// An absent store is the normal state of most hosts: the plugin is not
// installed, so nothing is locked. It must not read as an error.
func TestReadLocksWithNoStore(t *testing.T) {
	fs := afero.NewMemMapFs()
	locks, err := readVersionlock(fs)
	require.NoError(t, err)
	assert.Empty(t, locks)
	assert.Empty(t, readZypperLocks(fs))
}

func TestReadVersionlockPrefersTheNewestStore(t *testing.T) {
	// RHEL 9 symlinks the yum path onto the dnf one; a host that carries both
	// a dnf5 and a dnf4 store should be read as dnf5.
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/dnf/versionlock.toml",
		[]byte("version = \"1.0\"\n\n[[packages]]\nname = \"from-toml\"\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/etc/dnf/plugins/versionlock.list",
		[]byte("from-list-1.0-1.el9.*\n"), 0o644))

	locks, err := readVersionlock(fs)
	require.NoError(t, err)
	assert.True(t, locks.has("from-toml"))
	assert.False(t, locks.has("from-list"))
}

func TestLockedNamesGlob(t *testing.T) {
	locks := lockedNames{"kernel*": struct{}{}, "nginx": struct{}{}}
	assert.True(t, locks.has("kernel-core"), "a glob lock covers the packages it matches")
	assert.True(t, locks.has("nginx"))
	assert.False(t, locks.has("bash"))
	assert.False(t, lockedNames{}.has("anything"), "an empty store locks nothing")
	assert.False(t, locks.has(""), "an empty name matches nothing")
}

// The opkg status fixture in this repo has carried a held package since before
// this field existed: `Status: install hold installed` on libc. It is the one
// fixture that already contained the shape, so it is the one that proves the
// status-file path end to end rather than proving the helper in isolation.
func TestOpkgFixtureReportsTheHeldPackage(t *testing.T) {
	raw, err := os.ReadFile("testdata/packages_opkg_statusfile.toml")
	require.NoError(t, err)

	// pull the embedded status file out of the mock fixture
	content := string(raw)
	start := strings.Index(content, `[files."/usr/lib/opkg/status"]`)
	require.GreaterOrEqual(t, start, 0)
	start = strings.Index(content[start:], `"""`) + start + 3
	end := strings.Index(content[start:], `"""`) + start

	pkgs, err := ParseOpkgPackages(strings.NewReader(content[start:end]))
	require.NoError(t, err)
	require.NotEmpty(t, pkgs)

	pinned := map[string]bool{}
	for _, p := range pkgs {
		pinned[p.Name] = p.Pinned
	}
	// Both of the fixture's held packages, and only those two.
	assert.True(t, pinned["libc"], "libc carries `Status: install hold installed`")
	assert.True(t, pinned["libpthread"], "libpthread carries it too")

	var held []string
	for name, isPinned := range pinned {
		if isPinned {
			held = append(held, name)
		}
	}
	assert.ElementsMatch(t, []string{"libc", "libpthread"}, held,
		"exactly the held packages are pinned, out of %d in the fixture", len(pinned))
}

// /etc/dnf/versionlock.toml on Fedora 44: a lock from `dnf versionlock add`
// and an entry as `dnf versionlock exclude` writes it. The exclude only keeps
// one version out (`dnf versionlock list` prints `evr != 3:2.0-1` and
// check-update still offers the update), so it does not hold the package.
const fedora44VersionlockTOML = `version = "1.0"

[[packages]]
name = "g03-lock"
comment = "Added by 'versionlock add' command on 2026-10-03 00:35:13"

[[packages.conditions]]
key = "evr"
comparator = "="
value = "1.0-1"

[[packages]]
name = "g03-epoch"
comment = "Added by 'versionlock exclude' command on 2026-10-03 01:56:44"

[[packages.conditions]]
key = "evr"
comparator = "!="
value = "3:2.0-1"
`

func TestParseVersionlockTOMLExcludeIsNotAPin(t *testing.T) {
	locks := parseVersionlockTOML([]byte(fedora44VersionlockTOML))
	assert.True(t, locks.has("g03-lock"))
	assert.False(t, locks.has("g03-epoch"), "an exclude entry keeps one version out, it holds nothing")
}

// The dnf4 (AlmaLinux 9) and yum (RHEL 7) stores write an exclude as a line
// starting with `!`.
func TestParseVersionlockListExcludeIsNotAPin(t *testing.T) {
	dnf4 := "\n# Added lock on Sat Oct  3 00:35:17 2026\ng03-lock-0:1.0-1.*\n\n# Added exclude on g03\n!g03-vlexcl-0:1.5-1.*\n"
	yum3 := "\n# Added locks on Sat Oct  3 00:35:13 2026\n0:g03-lock-1.0-1.*\n\n# Added exclude on g03\n!0:g03-vlexcl-1.5-1.*\n"
	for name, content := range map[string]string{"dnf4": dnf4, "yum3": yum3} {
		locks := parseVersionlockList(content)
		assert.True(t, locks.has("g03-lock"), name)
		assert.Len(t, locks, 1, name)
	}
}

// permissionFs refuses to open one path, as the local filesystem does for a
// non-root user and a 0600 file.
type permissionFs struct {
	afero.Fs
	denied string
}

func (p permissionFs) Open(name string) (afero.File, error) {
	if name == p.denied {
		return nil, &iofs.PathError{Op: "open", Path: name, Err: iofs.ErrPermission}
	}
	return p.Fs.Open(name)
}

// `chmod 600 /etc/dnf/plugins/versionlock.list` and a non-root scan: the
// store exists and holds g03-lock, so "nothing is locked" is a guess.
func TestReadVersionlockUnreadableStoreIsAnError(t *testing.T) {
	mem := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(mem, "/etc/dnf/plugins/versionlock.list", []byte("g03-lock-0:1.0-1.*\n"), 0o600))
	locks, err := readVersionlock(permissionFs{Fs: mem, denied: "/etc/dnf/plugins/versionlock.list"})
	require.Error(t, err)
	assert.ErrorIs(t, err, iofs.ErrPermission)
	assert.Nil(t, locks)
}

// enabled = 0 in the plugin's configuration turns the locks off: dnf
// check-update offers g03-lock 2.0-1 again.
func TestReadVersionlockDisabledPlugin(t *testing.T) {
	for _, dir := range []string{"/etc/dnf/plugins", "/etc/yum/pluginconf.d"} {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, dir+"/versionlock.conf",
			[]byte("[main]\nenabled = 0\nlocklist = "+dir+"/versionlock.list\n"), 0o644))
		require.NoError(t, afero.WriteFile(fs, dir+"/versionlock.list", []byte("g03-lock-0:1.0-1.*\n"), 0o644))
		locks, err := readVersionlock(fs)
		require.NoError(t, err, dir)
		assert.False(t, locks.has("g03-lock"), dir)
	}
}

// The plugin reads its locks from the file its configuration names.
func TestReadVersionlockFollowsLocklist(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/yum/pluginconf.d/versionlock.conf",
		[]byte("[main]\nenabled = 1\nlocklist = /etc/yum/locks.list\n# show_hint = 1\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/etc/yum/locks.list", []byte("0:g03-lock-1.0-1.*\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/etc/yum/pluginconf.d/versionlock.list", []byte("0:stale-1.0-1.*\n"), 0o644))
	locks, err := readVersionlock(fs)
	require.NoError(t, err)
	assert.True(t, locks.has("g03-lock"))
	assert.False(t, locks.has("stale"))
}

// The configuration as AlmaLinux 9 and RHEL 7 ship it, plus the spellings
// dnf and yum accept for a boolean.
func TestParseVersionlockConf(t *testing.T) {
	enabled, list := parseVersionlockConf("[main]\nenabled = 1\nlocklist = /etc/dnf/plugins/versionlock.list\n")
	assert.True(t, enabled)
	assert.Equal(t, "/etc/dnf/plugins/versionlock.list", list)

	for _, off := range []string{"0", "False", "no", "off"} {
		enabled, _ = parseVersionlockConf("[main]\nenabled=" + off + "\n")
		assert.False(t, enabled, off)
	}
	// only [main] counts
	enabled, _ = parseVersionlockConf("[main]\nenabled = 1\n[other]\nenabled = 0\n")
	assert.True(t, enabled)
	// a commented-out setting is not a setting
	enabled, _ = parseVersionlockConf("[main]\n# enabled = 0\n")
	assert.True(t, enabled)
}

// With StructuredErrors an unreadable store makes pinned an error on every
// package; without it, v13's false is kept.
func TestMarkPinnedUnreadableStore(t *testing.T) {
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })
	denied := &iofs.PathError{Op: "open", Path: "/etc/dnf/versionlock.toml", Err: iofs.ErrPermission}

	plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)}))
	pkgs := markPinned([]Package{{Name: "g03-lock"}}, nil, denied)
	assert.False(t, pkgs[0].Pinned)
	assert.NoError(t, pkgs[0].PinnedErr)

	plugin.ReadFeatures([]byte(mql.Features{byte(mql.StructuredErrors)}))
	pkgs = markPinned([]Package{{Name: "g03-lock"}}, nil, denied)
	require.Error(t, pkgs[0].PinnedErr)
	assert.ErrorIs(t, pkgs[0].PinnedErr, llx.ErrForbidden)
}

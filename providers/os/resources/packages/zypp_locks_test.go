// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	iofs "io/fs"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// The installed test packages on openSUSE Leap 16.0, SLES 15 SP7 and SLES 16.0,
// with an update to 2.0-1 (3:2.0-1 for g03-epoch) in the repositories.
var (
	g03Uni   = Package{Name: "g03-uni", Version: "1.0-1", Arch: "x86_64"}
	g03Epoch = Package{Name: "g03-epoch", Version: "3:1.0-1", Epoch: "3", Arch: "x86_64"}
	g03Multi = Package{Name: "g03-multi", Version: "1.0-1", Arch: "i686"}
	g03Lock  = Package{Name: "g03-lock", Version: "1.0-1", Arch: "x86_64"}
)

// Each lock is appended to the store the three SUSE hosts carry
// (testdata/zypp_locks_g03: g03-globlock*, g03-lock, plymouth*), and pinned
// must agree with whether `zypper -n --xmlout lu` still offers the update.
func TestZypperLocksMatchZypper(t *testing.T) {
	base, err := os.ReadFile("testdata/zypp_locks_g03")
	require.NoError(t, err)

	tests := []struct {
		name string
		lock string
		pkg  Package
		held bool
	}{
		// the report's L1 to L10
		{"L1 zypper al 'g03-multi.i686' is a name", "type: package\nmatch_type: glob\ncase_sensitive: on\nsolvable_name: g03-multi.i686", g03Multi, false},
		{"L2 case_sensitive off", "type: package\nmatch_type: exact\ncase_sensitive: off\nsolvable_name: G03-UNI", g03Uni, true},
		{"L3 regex", "type: package\nmatch_type: regex\ncase_sensitive: on\nsolvable_name: ^g03-uni$", g03Uni, true},
		{"L4 version below the installed one", "type: package\nversion: < 1.0\nmatch_type: glob\ncase_sensitive: on\nsolvable_name: g03-epoch", g03Epoch, false},
		{"L4b version above 1.0 covers the installed one", "type: package\nversion: > 1.0\nmatch_type: glob\ncase_sensitive: on\nsolvable_name: g03-epoch", g03Epoch, true},
		{"L10 pattern lock", "type: pattern\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-uni", g03Uni, false},

		// further probes against zypper on SLES 16.0 (libzypp 17.38)
		{"no match_type is a substring", "type: package\nsolvable_name: g03-un", g03Uni, true},
		{"no case_sensitive folds case", "type: package\nsolvable_name: G03-UNI", g03Uni, true},
		{"no type holds packages", "match_type: exact\nsolvable_name: g03-uni", g03Uni, true},
		{"exact is not a prefix", "type: package\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-un", g03Uni, false},
		{"words", "type: package\nmatch_type: words\ncase_sensitive: on\nsolvable_name: g03", g03Epoch, true},
		{"glob case_sensitive off", "type: package\nmatch_type: glob\ncase_sensitive: off\nsolvable_name: G03-UN*", g03Uni, true},
		{"glob case_sensitive on", "type: package\nmatch_type: glob\ncase_sensitive: on\nsolvable_name: G03-UN*", g03Uni, false},
		{"regex is unanchored", "type: package\nmatch_type: regex\ncase_sensitive: on\nsolvable_name: 03-un", g03Uni, true},
		{"second solvable_name", "type: package\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-uni\nsolvable_name: g03-epoch", g03Epoch, true},
		{"solvable_arch i686", "type: package\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-multi\nsolvable_arch: i686", g03Multi, true},
		{"solvable_arch x86_64 holds every x86_64 package", "type: package\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-multi\nsolvable_arch: x86_64", g03Uni, true},
		{"solvable_arch i686 holds no x86_64 package", "type: package\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-multi\nsolvable_arch: i686", g03Uni, false},
		{"= installed", "type: package\nversion: = 3:1.0-1\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-epoch", g03Epoch, true},
		{"== installed", "type: package\nversion: == 3:1.0-1\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-epoch", g03Epoch, true},
		{"= without the epoch is epoch 0", "type: package\nversion: = 1.0-1\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-epoch", g03Epoch, false},
		{"= without the release matches any release", "type: package\nversion: = 3:1.0\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-epoch", g03Epoch, true},
		{"< the update", "type: package\nversion: < 3:2.0\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-epoch", g03Epoch, true},
		{"<= 1.0 is below epoch 3", "type: package\nversion: <= 1.0\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-epoch", g03Epoch, false},
		{">= installed", "type: package\nversion: >= 3:1.0-1\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-epoch", g03Epoch, true},
		{"> installed locks every newer edition", "type: package\nversion: > 3:1.0-1\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-epoch", g03Epoch, true},
		{"> the update", "type: package\nversion: > 3:2.0-1\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-epoch", g03Epoch, false},
		{"!= the update", "type: package\nversion: != 3:2.0-1\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-epoch", g03Epoch, true},
		{"< 2.0", "type: package\nversion: < 2.0\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-uni", g03Uni, true},
		{"> 1.0 over 1.0-1", "type: package\nversion: > 1.0\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-uni", g03Uni, true},
		{"> 1.0-1", "type: package\nversion: > 1.0-1\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-uni", g03Uni, true},
		{">= 0", "type: package\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-uni\nversion: >= 0", g03Uni, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			locks := parseZypperLocks(string(base) + "\n" + tc.lock + "\n")
			assert.Equal(t, tc.held, locks.holds(tc.pkg))
			// the stock locks keep holding what they held
			assert.True(t, locks.holds(g03Lock))
			assert.True(t, locks.holds(Package{Name: "g03-globlock-a", Version: "1.0-1"}))
		})
	}
}

// `= 2.0` locks the update and not the installed 1.0: it keeps one version
// out, like dnf's versionlock exclude, and is not a pin.
func TestZypperLockOnANewerVersionIsNotAPin(t *testing.T) {
	locks := parseZypperLocks("type: package\nversion: = 3:2.0-1\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-epoch\n")
	assert.False(t, locks.holds(g03Epoch))
}

// The store saved with CRLF line ends: zypper lists three locks whose names
// end in CR and holds none of them (report L7).
func TestZypperLocksCRLFHoldNothing(t *testing.T) {
	raw, err := os.ReadFile("testdata/zypp_locks_crlf")
	require.NoError(t, err)
	locks := parseZypperLocks(string(raw))
	assert.False(t, locks.holds(g03Lock))
	assert.False(t, locks.holds(Package{Name: "g03-globlock-a"}))
}

// Separator lines that hold only spaces, and comment lines: zypper applies
// both locks (report L8).
func TestZypperLocksWhitespaceSeparators(t *testing.T) {
	locks := parseZypperLocks("\ntype: package\nmatch_type: glob\ncase_sensitive: on\nsolvable_name: g03-globlock*\n   \n# g03 comment\n\ntype: package\nmatch_type: glob\ncase_sensitive: on\nsolvable_name: g03-lock\n")
	assert.True(t, locks.holds(g03Lock))
	assert.True(t, locks.holds(Package{Name: "g03-globlock-a"}))
	assert.False(t, locks.holds(g03Uni))
}

func writeFiles(t *testing.T, files map[string]string) afero.Fs {
	fs := afero.NewMemMapFs()
	for p, content := range files {
		require.NoError(t, afero.WriteFile(fs, p, []byte(content), 0o644))
	}
	return fs
}

const g03Locks = "type: package\nmatch_type: glob\ncase_sensitive: on\nsolvable_name: g03-lock\n"

func TestReadZypperLocksConfig(t *testing.T) {
	stockConf := "[main]\n# locksfile.path = /etc/zypp/locks\n# locksfile.apply = true\n"

	t.Run("stock configuration", func(t *testing.T) {
		locks, err := readZypperLocks(writeFiles(t, map[string]string{
			zyppConfPath:      stockConf,
			"/etc/zypp/locks": g03Locks,
		}))
		require.NoError(t, err)
		assert.True(t, locks.holds(g03Lock))
	})

	// report L5: zypper offers g03-lock 2.0-1
	t.Run("locksfile.apply = false", func(t *testing.T) {
		locks, err := readZypperLocks(writeFiles(t, map[string]string{
			zyppConfPath:      "[main]\n# locksfile.path = /etc/zypp/locks\nlocksfile.apply = false\n",
			"/etc/zypp/locks": g03Locks,
		}))
		require.NoError(t, err)
		assert.False(t, locks.holds(g03Lock))
	})

	// probed on SLES 16.0: a drop-in turns the store off as well
	t.Run("locksfile.apply = false in a drop-in", func(t *testing.T) {
		locks, err := readZypperLocks(writeFiles(t, map[string]string{
			zyppConfPath:                        stockConf,
			"/etc/zypp/zypp.conf.d/90-off.conf": "[main]\nlocksfile.apply = false\n",
			"/etc/zypp/locks":                   g03Locks,
		}))
		require.NoError(t, err)
		assert.False(t, locks.holds(g03Lock))
	})

	t.Run("a later drop-in wins", func(t *testing.T) {
		locks, err := readZypperLocks(writeFiles(t, map[string]string{
			"/etc/zypp/zypp.conf.d/10-off.conf":    "[main]\nlocksfile.apply = false\n",
			"/usr/etc/zypp/zypp.conf.d/20-on.conf": "[main]\nlocksfile.apply = on\n",
			"/etc/zypp/zypp.conf.d/30-ignored.txt": "[main]\nlocksfile.apply = false\n",
			"/etc/zypp/locks":                      g03Locks,
		}))
		require.NoError(t, err)
		assert.True(t, locks.holds(g03Lock))
	})

	t.Run("a drop-in in /etc replaces the /usr/etc one of the same name", func(t *testing.T) {
		locks, err := readZypperLocks(writeFiles(t, map[string]string{
			zyppVendorConfPath:                    "[main]\nlocksfile.apply = false\n",
			"/usr/etc/zypp/zypp.conf.d/10-a.conf": "[main]\nlocksfile.apply = on\n",
			"/etc/zypp/zypp.conf.d/10-a.conf":     "[main]\n",
			"/etc/zypp/locks":                     g03Locks,
		}))
		require.NoError(t, err)
		assert.False(t, locks.holds(g03Lock))
	})

	t.Run("/etc/zypp/zypp.conf replaces the vendor file", func(t *testing.T) {
		locks, err := readZypperLocks(writeFiles(t, map[string]string{
			zyppVendorConfPath: "[main]\nlocksfile.apply = false\n",
			zyppConfPath:       "",
			"/etc/zypp/locks":  g03Locks,
		}))
		require.NoError(t, err)
		assert.True(t, locks.holds(g03Lock))
	})

	t.Run("the vendor file applies without /etc/zypp/zypp.conf", func(t *testing.T) {
		locks, err := readZypperLocks(writeFiles(t, map[string]string{
			zyppVendorConfPath: "[main]\nlocksfile.apply = false\n",
			"/etc/zypp/locks":  g03Locks,
		}))
		require.NoError(t, err)
		assert.False(t, locks.holds(g03Lock))
	})

	// report L6: zypper holds g03-uni from the relocated store
	t.Run("locksfile.path", func(t *testing.T) {
		locks, err := readZypperLocks(writeFiles(t, map[string]string{
			zyppConfPath:          "[main]\nlocksfile.path = /etc/zypp/locks.g03\n# locksfile.apply = true\n",
			"/etc/zypp/locks":     g03Locks,
			"/etc/zypp/locks.g03": "type: package\nmatch_type: exact\ncase_sensitive: on\nsolvable_name: g03-uni\n",
		}))
		require.NoError(t, err)
		assert.True(t, locks.holds(g03Uni))
		assert.False(t, locks.holds(g03Lock), "the default store is not read")
	})

	t.Run("configdir moves the default store", func(t *testing.T) {
		locks, err := readZypperLocks(writeFiles(t, map[string]string{
			zyppConfPath:      "[main]\nconfigdir = /srv/zypp\n",
			"/srv/zypp/locks": g03Locks,
		}))
		require.NoError(t, err)
		assert.True(t, locks.holds(g03Lock))
	})
}

// report L9: `chmod 600 /etc/zypp/locks` and a non-root scan. zypper itself
// fails ("Error reading the locks file", rc 4), and root reads g03-lock held,
// so "nothing pinned" is a guess.
func TestReadZypperLocksUnreadableStoreIsAnError(t *testing.T) {
	mem := writeFiles(t, map[string]string{"/etc/zypp/locks": g03Locks})
	locks, err := readZypperLocks(permissionFs{Fs: mem, denied: "/etc/zypp/locks"})
	require.Error(t, err)
	assert.ErrorIs(t, err, iofs.ErrPermission)
	assert.Nil(t, locks)

	mem = writeFiles(t, map[string]string{zyppConfPath: "[main]\n", "/etc/zypp/locks": g03Locks})
	_, err = readZypperLocks(permissionFs{Fs: mem, denied: zyppConfPath})
	assert.ErrorIs(t, err, iofs.ErrPermission, "an unreadable zypp.conf leaves the store unknown")
}

// With StructuredErrors the unreadable store makes pinned a Forbidden error on
// every SUSE package; without it v13's false stays.
func TestMarkPinnedUnreadableZypperStore(t *testing.T) {
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })
	mem := writeFiles(t, map[string]string{"/etc/zypp/locks": g03Locks})
	locks, readErr := readZypperLocks(permissionFs{Fs: mem, denied: "/etc/zypp/locks"})

	plugin.ReadFeatures([]byte(mql.Features{byte(mql.StructuredErrors)}))
	pkgs := markPinned([]Package{g03Lock}, locks, readErr)
	assert.ErrorIs(t, pkgs[0].PinnedErr, llx.ErrForbidden)
	assert.False(t, pkgs[0].Pinned)
}

func TestParseZyppLockConfigBooleans(t *testing.T) {
	for _, off := range []string{"0", "no", "off", "false", "False", "OFF"} {
		assert.False(t, parseZyppLockConfig([]byte("[main]\nlocksfile.apply = "+off+"\n")).apply, off)
	}
	assert.True(t, parseZyppLockConfig([]byte("[main]\nlocksfile.apply=false\nlocksfile.apply = yes\n")).apply)
	assert.True(t, parseZyppLockConfig([]byte("[other]\nlocksfile.apply = false\n")).apply, "only [main] counts")
	assert.True(t, parseZyppLockConfig([]byte("[main]\n#locksfile.apply = false\n")).apply)
	assert.Equal(t, "/etc/zypp/locks", parseZyppLockConfig().path)
}

func TestRpmvercmp(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"1.10", "1.9", 1},
		{"1.010", "1.10", 0},
		{"1.0a", "1.0", 1},
		{"1.0", "1.0a", -1},
		{"1.a", "1.1", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0^git1", "1.0", 1},
		{"1.0^git1", "1.0.1", -1},
		{"1.0^", "1.0", 1},
		{"1_0", "1.0", 0},
		{"5.0", "5", 1},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, rpmvercmp(tc.a, tc.b), "%s vs %s", tc.a, tc.b)
	}
}

func TestCompareEVRMatch(t *testing.T) {
	assert.Equal(t, 1, compareEVRMatch("3:1.0-1", "1.0"), "a missing epoch is 0")
	assert.Equal(t, 0, compareEVRMatch("3:1.0-1", "3:1.0"), "a missing release matches any")
	assert.Equal(t, -1, compareEVRMatch("3:1.0-1", "3:1.0-2"))
	assert.Equal(t, 0, compareEVRMatch("1.0-1", "0:1.0-1"))
	assert.Equal(t, -1, compareEVRMatch("1.0-1", "1:0.1"))
}

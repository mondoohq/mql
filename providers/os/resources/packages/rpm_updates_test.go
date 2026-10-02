// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func TestRpmUpdateParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/updates_rpm.toml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := mock.RunCommand("python")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)

	m, err := ParseRpmUpdates(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 8, len(m), "detected the right amount of package updates")

	update := m["python-libs"]
	assert.Equal(t, "python-libs", update.Name, "pkg name detected")
	assert.Equal(t, "", update.Version, "pkg version detected")
	assert.Equal(t, "0:2.7.5-69.el7_5", update.Available, "pkg available version detected")

	update = m["binutils"]
	assert.Equal(t, "binutils", update.Name, "pkg name detected")
	assert.Equal(t, "", update.Version, "pkg version detected")
	assert.Equal(t, "0:2.27-28.base.el7_5.1", update.Available, "pkg available version detected")
}

func TestZypperUpdateParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/updates_zypper.toml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := mock.RunCommand("zypper -n --xmlout list-updates")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)

	m, err := ParseZypperUpdates(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 22, len(m), "detected the right amount of package updates")

	update := m["aaa_base.x86_64"]
	assert.Equal(t, "aaa_base", update.Name, "pkg name detected")
	assert.Equal(t, "13.2+git20140911.61c1681-28.3.1", update.Version, "pkg version detected")

	update = m["bash.x86_64"]
	assert.Equal(t, "bash", update.Name, "pkg name detected")
	assert.Equal(t, "4.3-83.3.1", update.Version, "pkg version detected")
}

// From `zypper -n --xmlout list-updates` on openSUSE Leap 16.0 with the g03
// test packages installed from a local repository.
func TestParseZypperUpdatesArchChange(t *testing.T) {
	f, err := os.Open("./testdata/zypper-lu-leap16-g03.xml")
	require.NoError(t, err)
	defer f.Close()

	m, err := ParseZypperUpdates(f)
	require.NoError(t, err)

	// installed as x86_64, updated by a noarch build; the installed arch is
	// in arch-old and is what the update is keyed and joined on
	require.Contains(t, m, "g03-archchg.x86_64")
	assert.Equal(t, PackageUpdate{Name: "g03-archchg", Version: "1.0-1", Arch: "x86_64", Available: "2.0-1"}, m["g03-archchg.x86_64"])
	assert.NotContains(t, m, "g03-archchg.noarch")

	assert.Equal(t, PackageUpdate{Name: "g03-multi", Version: "1.0-1", Arch: "i686", Available: "2.0-1"}, m["g03-multi.i686"])
	assert.Equal(t, "3:2.0-1", m["g03-epoch.x86_64"].Available)
	assert.Equal(t, "noarch", m["ca-certificates-mozilla.noarch"].Arch)
}

func zypperResult(t *testing.T, file string, exit int) *shared.Command {
	t.Helper()
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	return &shared.Command{Stdout: bytes.NewBuffer(raw), Stderr: &bytes.Buffer{}, ExitStatus: exit}
}

// The failures are real `zypper -n --xmlout list-updates` runs on openSUSE
// Leap 16.0. Each one printed fewer updates than were pending, and each was
// read as "every package is up to date".
func TestParseZypperListUpdatesResult(t *testing.T) {
	t.Run("a finished check", func(t *testing.T) {
		m, err := parseZypperListUpdatesResult(zypperResult(t, "./testdata/zypper-lu-leap16-g03.xml", 0))
		require.NoError(t, err)
		assert.Equal(t, "2.0-1", m["g03-archchg.x86_64"].Available)
	})

	t.Run("100 to 103 are informational", func(t *testing.T) {
		for _, exit := range []int{100, 101, 102, 103} {
			m, err := parseZypperListUpdatesResult(zypperResult(t, "./testdata/zypper-lu-leap16-g03.xml", exit))
			require.NoError(t, err, "exit %d", exit)
			assert.Contains(t, m, "g03-epoch.x86_64")
		}
	})

	t.Run("the zypp lock is held", func(t *testing.T) {
		m, err := parseZypperListUpdatesResult(zypperResult(t, "./testdata/zypper-lu-locked-leap16.xml", 7))
		require.ErrorIs(t, err, ErrUpdateCheckFailed)
		assert.Contains(t, err.Error(), "exit status 7")
		assert.Contains(t, err.Error(), "System management is locked by the application with pid 15950 (zypper). Close this application")
		assert.Empty(t, m)
	})

	// g03repo carries the g03 updates and its metadata is gone. zypper skips
	// it, lists the updates of the other repositories and exits 106.
	t.Run("a repository is skipped", func(t *testing.T) {
		m, err := parseZypperListUpdatesResult(zypperResult(t, "./testdata/zypper-lu-broken-repo-leap16.xml", 106))
		require.ErrorIs(t, err, ErrUpdateCheckFailed)
		assert.Contains(t, err.Error(), "exit status 106")
		assert.Contains(t, err.Error(), "Repository 'g03repo' is invalid.")
		assert.NotContains(t, err.Error(), "Skipping repository", "a warning is not an error")
		// the updates of the repositories zypper did read are kept
		assert.Equal(t, "2.90-160000.1.1", m["ca-certificates-mozilla.noarch"].Available)
		assert.NotContains(t, m, "g03-epoch.x86_64")
	})

	// As a user who cannot write the metadata cache, zypper loads no
	// repository at all, lists no update, and exits 0.
	t.Run("no repository could be loaded, exit 0", func(t *testing.T) {
		m, err := parseZypperListUpdatesResult(zypperResult(t, "./testdata/zypper-lu-nonroot-nocache-leap16.xml", 0))
		require.ErrorIs(t, err, ErrUpdateCheckFailed)
		assert.Contains(t, err.Error(), "Resolvables from 'g03repo' not loaded because of error.")
		assert.NotContains(t, err.Error(), "out-of-date", "an info message is not an error")
		assert.Empty(t, m)
	})

	t.Run("output that is not zypper XML", func(t *testing.T) {
		cmd := &shared.Command{Stdout: bytes.NewBufferString("zypper: command not found\n"), Stderr: &bytes.Buffer{}, ExitStatus: 0}
		_, err := parseZypperListUpdatesResult(cmd)
		require.ErrorIs(t, err, ErrUpdateCheckFailed)

		cmd = &shared.Command{Stdout: bytes.NewBufferString(""), Stderr: &bytes.Buffer{}, ExitStatus: 127}
		_, err = parseZypperListUpdatesResult(cmd)
		require.ErrorIs(t, err, ErrUpdateCheckFailed)
		assert.Contains(t, err.Error(), "exit status 127")
	})

	t.Run("long messages are capped", func(t *testing.T) {
		long := `<?xml version='1.0'?><stream><message type="error">` + strings.Repeat("x", 2000) + `</message></stream>`
		cmd := &shared.Command{Stdout: bytes.NewBufferString(long), Stderr: &bytes.Buffer{}, ExitStatus: 4}
		_, err := parseZypperListUpdatesResult(cmd)
		require.ErrorIs(t, err, ErrUpdateCheckFailed)
		assert.Less(t, len(err.Error()), zypperMaxErr+200)
	})
}

// staticAvailableConn is a connection that cannot run commands, like an
// image or a filesystem.
type staticAvailableConn struct {
	shared.Connection
}

func (staticAvailableConn) Capabilities() shared.Capabilities {
	return shared.Capability_File
}

// When rpm cannot be run the manager reads the rpm database without it and has
// no update check. On a host that runs commands (rpm failed to run, or the
// probe failed under --sudo) the empty map it returned read as "up to date".
func TestRpmStaticAvailable(t *testing.T) {
	base, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{}))
	require.NoError(t, err)

	live := &RpmPkgManager{conn: base, staticChecked: true, static: true}
	_, err = live.Available()
	require.ErrorIs(t, err, ErrUpdateCheckFailed)

	suse := &SusePkgManager{RpmPkgManager{conn: base, staticChecked: true, static: true}}
	_, err = suse.Available()
	require.ErrorIs(t, err, ErrUpdateCheckFailed)

	image := &RpmPkgManager{conn: staticAvailableConn{base}, staticChecked: true, static: true}
	m, err := image.Available()
	require.NoError(t, err)
	assert.Empty(t, m)
}

// TestParseRpmCheckUpdate reads `dnf check-update` captured from live EC2
// hosts on 2026-09-18. Before this parser existed the rpm reader ran a Python
// 2 / yum-cli snippet that no longer runs on either host, so both reported no
// updates at all.
func TestParseRpmCheckUpdate(t *testing.T) {
	t.Run("rhel9, including the Obsoleting Packages section", func(t *testing.T) {
		f, err := os.Open("./testdata/dnf-rhel9.txt")
		require.NoError(t, err)
		defer f.Close()

		m, err := ParseRpmCheckUpdate(f)
		require.NoError(t, err)
		require.NotEmpty(t, m)

		// epoch stays on the available version, as it is printed
		nm, ok := m["NetworkManager.x86_64"]
		require.True(t, ok)
		assert.Equal(t, "1:1.54.3-5.el9_8", nm.Available)
		assert.Equal(t, "x86_64", nm.Arch)
		assert.Equal(t, "rhel-9-baseos-rhui-rpms", nm.Repo)

		acl, ok := m["acl.x86_64"]
		require.True(t, ok)
		assert.Equal(t, "2.4.0-1.el9_8", acl.Available)

		// grub2-tools appears ONLY as the indented @System side of an
		// obsoletes pair, carrying the older installed version. Reading it
		// would advertise a downgrade as an available update.
		if g, ok := m["grub2-tools.x86_64"]; ok {
			assert.NotEqual(t, "1:2.06-105.el9_6.2", g.Available,
				"picked up the obsoleted @System line")
			assert.NotEqual(t, "@System", g.Repo)
		}
		for name, u := range m {
			assert.NotEqual(t, "@System", u.Repo, "package %s", name)
			assert.NotEmpty(t, u.Arch, "package %s has no arch", name)
		}
	})

	t.Run("alma9", func(t *testing.T) {
		f, err := os.Open("./testdata/dnf-alma9.txt")
		require.NoError(t, err)
		defer f.Close()
		m, err := ParseRpmCheckUpdate(f)
		require.NoError(t, err)

		k, ok := m["kernel.x86_64"]
		require.True(t, ok)
		assert.Equal(t, "5.14.0-687.48.1.el9_8", k.Available)
		assert.Equal(t, "x86_64", k.Arch)
		assert.Equal(t, "baseos", k.Repo)
	})

	t.Run("no updates yields an empty map, not an error", func(t *testing.T) {
		m, err := ParseRpmCheckUpdate(bytes.NewBufferString(""))
		require.NoError(t, err)
		assert.Empty(t, m)
	})

	t.Run("headers and indented lines are ignored", func(t *testing.T) {
		m, err := ParseRpmCheckUpdate(bytes.NewBufferString(
			"Last metadata expiration check: 0:00:01 ago.\n\n" +
				"Obsoleting Packages\n" +
				"    grub2-tools.x86_64   1:2.06-105.el9_6.2   @System\n"))
		require.NoError(t, err)
		assert.Empty(t, m)
	})
}

func parseCheckUpdateFile(t *testing.T, path string) map[string]PackageUpdate {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	m, err := ParseRpmCheckUpdate(f)
	require.NoError(t, err)
	return m
}

// The g03 captures come from hosts with test packages from a local repo:
// g03-multi installed for i686 and x86_64, g03-archchg moving from x86_64 to
// noarch, a name too long for yum 3's first column, and g03-new obsoleting
// g03-old.
func TestParseRpmCheckUpdateG03(t *testing.T) {
	for _, tc := range []struct {
		file  string
		count int
	}{
		{"./testdata/yum-rhel7-g03.txt", 8},
		{"./testdata/dnf-alma9-g03.txt", 43},
		{"./testdata/dnf5-fedora44-g03.txt", 19},
	} {
		t.Run(tc.file, func(t *testing.T) {
			m := parseCheckUpdateFile(t, tc.file)
			assert.Len(t, m, tc.count)

			// both architectures of a multilib package keep their update
			assert.Equal(t, PackageUpdate{Name: "g03-multi", Arch: "i686", Available: "2.0-1", Repo: "g03repo"}, m["g03-multi.i686"])
			assert.Equal(t, PackageUpdate{Name: "g03-multi", Arch: "x86_64", Available: "2.0-1", Repo: "g03repo"}, m["g03-multi.x86_64"])

			// yum 3 printed this name on its own line, the version below it
			long := "g03-a-very-long-package-name-that-exceeds-the-check-update-column-width"
			assert.Equal(t, PackageUpdate{Name: long, Arch: "x86_64", Available: "2.0-1", Repo: "g03repo"}, m[long+".x86_64"])

			assert.Equal(t, "noarch", m["g03-archchg.noarch"].Arch)
			assert.Equal(t, "3:2.0-1", m["g03-epoch.x86_64"].Available)

			// the obsoleted, installed side of an obsoletes pair is no update
			assert.NotContains(t, m, "g03-old.x86_64")
		})
	}
}

func TestParseRpmCheckUpdateWrappedLines(t *testing.T) {
	m, err := ParseRpmCheckUpdate(bytes.NewBufferString(strings.Join([]string{
		// a wrapped name whose continuation never comes is dropped, and the
		// following package line is still read on its own
		"first-long-name.x86_64",
		"bash.x86_64                    5.2-1        base",
		// an indented line that does not follow a wrapped name is no update
		"                               9.9-1        base",
		"Obsoleting Packages",
		"g03-new.x86_64                 2.0-1        g03repo",
		"    g03-old-with-a-long-name.x86_64",
		"                               1.0-1        installed",
		// the repo yum 3 names for the obsoleted, installed package
		"g03-unindented.x86_64          1.0-1        installed",
		"",
	}, "\n")))
	require.NoError(t, err)
	assert.Equal(t, map[string]PackageUpdate{
		"bash.x86_64":    {Name: "bash", Arch: "x86_64", Available: "5.2-1", Repo: "base"},
		"g03-new.x86_64": {Name: "g03-new", Arch: "x86_64", Available: "2.0-1", Repo: "g03repo"},
	}, m)
}

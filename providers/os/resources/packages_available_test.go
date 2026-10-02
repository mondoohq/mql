// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/packages"
	"go.mondoo.com/mql/utils/syncx"
)

// rpmUpdateHostConn answers the commands packages.list and package.available
// run on a running rpm host, and counts the update checks. Everything else
// (asset, filesystem) comes from an empty mock connection.
type rpmUpdateHostConn struct {
	shared.Connection

	updateStdout string
	updateExit   int

	mu           sync.Mutex
	updateChecks int
}

const rpmUpdateHostList = "openssl 1:3.0.8-1.amzn2023.0.14 x86_64__Amazon Linux__TLS toolkit__Apache-2.0__1700000000\n" +
	"bash 0:5.2.15-1.amzn2023.0.2 x86_64__Amazon Linux__The GNU Bourne Again shell__GPLv3+__1700000000\n"

func (c *rpmUpdateHostConn) RunCommand(command string) (*shared.Command, error) {
	out := func(stdout string, exit int) *shared.Command {
		return &shared.Command{
			Command:    command,
			Stdout:     bytes.NewBufferString(stdout),
			Stderr:     &bytes.Buffer{},
			ExitStatus: exit,
		}
	}
	switch {
	case command == "rpm --version":
		return out("RPM version 4.16.1.3\n", 0), nil
	case strings.HasPrefix(command, "rpm -qa"):
		return out(rpmUpdateHostList, 0), nil
	case strings.Contains(command, "check-update") || strings.HasPrefix(command, "zypper "):
		c.mu.Lock()
		c.updateChecks++
		c.mu.Unlock()
		return out(c.updateStdout, c.updateExit), nil
	}
	return c.Connection.RunCommand(command)
}

func (c *rpmUpdateHostConn) checks() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.updateChecks
}

func newRpmUpdateHost(t *testing.T, updateStdout string, updateExit int) (*plugin.Runtime, *rpmUpdateHostConn) {
	t.Helper()
	base, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "amazonlinux", Version: "2023", Family: []string{"linux", "unix", "os"}},
	}, mock.WithData(&mock.TomlData{}))
	require.NoError(t, err)

	conn := &rpmUpdateHostConn{Connection: base, updateStdout: updateStdout, updateExit: updateExit}
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
		Callback:   &providerCallbacks{},
	}, conn
}

func listPackagesByName(t *testing.T, runtime *plugin.Runtime) map[string]*mqlPackage {
	t.Helper()
	obj, err := CreateResource(runtime, "packages", nil)
	require.NoError(t, err)
	list := obj.(*mqlPackages).GetList()
	require.NoError(t, list.Error)

	res := map[string]*mqlPackage{}
	for _, raw := range list.Data {
		pkg := raw.(*mqlPackage)
		res[pkg.Name.Data] = pkg
	}
	require.Contains(t, res, "openssl")
	require.Contains(t, res, "bash")
	return res
}

// Listing packages must not ask the package manager for updates: on rpm hosts
// that is `dnf check-update`, which refreshes stale repository metadata and
// is expensive on a small host, on scans that never read available or
// outdated.
func TestPackagesListDoesNotRunTheUpdateCheck(t *testing.T) {
	runtime, conn := newRpmUpdateHost(t,
		"openssl.x86_64    1:3.0.8-1.amzn2023.0.18    amazonlinux\n", 100)

	pkgs := listPackagesByName(t, runtime)
	assert.Equal(t, 0, conn.checks(), "listing packages ran the update check")

	openssl := pkgs["openssl"]
	assert.Equal(t, "1:3.0.8-1.amzn2023.0.18", openssl.GetAvailable().Data)
	outdated := openssl.GetOutdated()
	require.NoError(t, outdated.Error)
	assert.True(t, outdated.Data)

	bash := pkgs["bash"]
	available := bash.GetAvailable()
	require.NoError(t, available.Error)
	assert.False(t, available.IsNull(), "no newer version is an empty string, not null")
	assert.Equal(t, "", available.Data)
	outdated = bash.GetOutdated()
	require.NoError(t, outdated.Error)
	assert.False(t, outdated.Data)

	assert.Equal(t, 1, conn.checks(), "the update check runs once per scan, not once per package")
}

type fakeUpdatesPkgManager struct {
	packages.OperatingSystemPkgManager
	updates map[string]packages.PackageUpdate
	err     error
	calls   int
}

func (f *fakeUpdatesPkgManager) Name() string { return "fake" }

func (f *fakeUpdatesPkgManager) Available() (map[string]packages.PackageUpdate, error) {
	f.calls++
	return f.updates, f.err
}

func lookupOK(t *testing.T, u *pkgUpdates, name, arch string) string {
	t.Helper()
	v, err := u.lookup(name, arch)
	require.NoError(t, err)
	return v
}

func TestPkgUpdatesLookup(t *testing.T) {
	t.Run("joins on name and arch", func(t *testing.T) {
		pm := &fakeUpdatesPkgManager{updates: map[string]packages.PackageUpdate{
			"libc6": {Name: "libc6", Arch: "amd64", Available: "2.39-0ubuntu8.9"},
		}}
		u := &pkgUpdates{pm: pm}

		assert.Equal(t, "2.39-0ubuntu8.9", lookupOK(t, u, "libc6", "amd64"))
		assert.Equal(t, "", lookupOK(t, u, "libc6", "i386"), "an update for another arch is not this package's update")
		assert.Equal(t, 1, pm.calls)
	})

	// Managers with no update support (pacman, macOS, COS) return an error.
	// They keep reporting no newer version, as they did before.
	t.Run("a manager that cannot report updates reports no newer version", func(t *testing.T) {
		for _, structured := range []bool{false, true} {
			withStructuredErrors(t, structured)
			pm := &fakeUpdatesPkgManager{err: errors.New("Available() not implemented for pacman")}
			u := &pkgUpdates{pm: pm}
			assert.Equal(t, "", lookupOK(t, u, "bash", "x86_64"))
			assert.Equal(t, "", lookupOK(t, u, "openssl", "x86_64"))
			assert.Equal(t, 1, pm.calls, "a failed check is not retried per package")
		}
	})

	// dnf check-update exits 1 as non-root on RHEL 8 to 10 (the RHUI client
	// certificate is unreadable) and whenever a repository fails. Nothing is
	// known about pending updates then.
	t.Run("a failed update check is an error", func(t *testing.T) {
		failed := fmt.Errorf("%w: check-update exited with status 1", packages.ErrUpdateCheckFailed)

		withStructuredErrors(t, true)
		pm := &fakeUpdatesPkgManager{err: failed}
		u := &pkgUpdates{pm: pm}
		_, err := u.lookup("bash", "x86_64")
		require.ErrorIs(t, err, packages.ErrUpdateCheckFailed)
		_, err = u.lookup("openssl", "x86_64")
		require.ErrorIs(t, err, packages.ErrUpdateCheckFailed)
		assert.Equal(t, 1, pm.calls, "a failed check is not retried per package")

		// v13 behavior without the StructuredErrors feature
		withStructuredErrors(t, false)
		u = &pkgUpdates{pm: &fakeUpdatesPkgManager{err: failed}}
		assert.Equal(t, "", lookupOK(t, u, "bash", "x86_64"))
	})

	// zypper prints the updates of the repositories it could read, then fails
	// on another one (exit 106). Those updates are real; the absence of one
	// is not.
	t.Run("a failed check keeps the updates it found", func(t *testing.T) {
		failed := fmt.Errorf("%w: zypper list-updates failed (exit status 106)", packages.ErrUpdateCheckFailed)
		partial := map[string]packages.PackageUpdate{
			"jq.x86_64": {Name: "jq", Arch: "x86_64", Available: "1.7.1-160000.2.1"},
		}

		withStructuredErrors(t, true)
		u := &pkgUpdates{pm: &fakeUpdatesPkgManager{updates: partial, err: failed}}
		assert.Equal(t, "1.7.1-160000.2.1", lookupOK(t, u, "jq", "x86_64"))
		_, err := u.lookup("g03-epoch", "x86_64")
		require.ErrorIs(t, err, packages.ErrUpdateCheckFailed)

		// v13 behavior without the StructuredErrors feature: the partial list
		withStructuredErrors(t, false)
		u = &pkgUpdates{pm: &fakeUpdatesPkgManager{updates: partial, err: failed}}
		assert.Equal(t, "1.7.1-160000.2.1", lookupOK(t, u, "jq", "x86_64"))
		assert.Equal(t, "", lookupOK(t, u, "g03-epoch", "x86_64"))
	})

	// From `dnf check-update` on RHEL 9 with the g03 test packages installed.
	t.Run("multilib and arch-changing rpm updates", func(t *testing.T) {
		f, err := os.Open("./packages/testdata/dnf-alma9-g03.txt")
		require.NoError(t, err)
		defer f.Close()
		updates, err := packages.ParseRpmCheckUpdate(f)
		require.NoError(t, err)
		// a package going from noarch to x86_64
		updates["g03-tonative.x86_64"] = packages.PackageUpdate{Name: "g03-tonative", Arch: "x86_64", Available: "2.0-1"}
		// only one half of a multilib pair has an update
		updates["g03-half.x86_64"] = packages.PackageUpdate{Name: "g03-half", Arch: "x86_64", Available: "2.0-1"}
		u := &pkgUpdates{pm: &fakeUpdatesPkgManager{updates: updates}}

		assert.Equal(t, "2.0-1", lookupOK(t, u, "g03-multi", "i686"))
		assert.Equal(t, "2.0-1", lookupOK(t, u, "g03-multi", "x86_64"))
		// installed as x86_64, updated by a noarch build
		assert.Equal(t, "2.0-1", lookupOK(t, u, "g03-archchg", "x86_64"))
		assert.Equal(t, "2.0-1", lookupOK(t, u, "g03-tonative", "noarch"))
		assert.Equal(t, "", lookupOK(t, u, "g03-half", "i686"), "an x86_64 update does not update the i686 package")
		assert.Equal(t, "", lookupOK(t, u, "g03-uptodate", "x86_64"))
	})
}

// A failed `dnf check-update` (exit 1, nothing on stdout) reached
// package.outdated as false for every package.
func TestPackageOutdatedFailedRpmCheck(t *testing.T) {
	withStructuredErrors(t, true)
	runtime, _ := newRpmUpdateHost(t, "", 1)
	pkgs := listPackagesByName(t, runtime)

	outdated := pkgs["openssl"].GetOutdated()
	require.ErrorIs(t, outdated.Error, packages.ErrUpdateCheckFailed)
	available := pkgs["bash"].GetAvailable()
	require.ErrorIs(t, available.Error, packages.ErrUpdateCheckFailed)
}

// newSuseUpdateHost is newRpmUpdateHost on SLES, where the update check is
// `zypper -n --xmlout list-updates`.
func newSuseUpdateHost(t *testing.T, updateFile string, updateExit int) *plugin.Runtime {
	t.Helper()
	raw, err := os.ReadFile(updateFile)
	require.NoError(t, err)
	base, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "sles", Version: "16.0", Family: []string{"suse", "linux", "unix", "os"}},
	}, mock.WithData(&mock.TomlData{}))
	require.NoError(t, err)
	conn := &rpmUpdateHostConn{Connection: base, updateStdout: string(raw), updateExit: updateExit}
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
		Callback:   &providerCallbacks{},
	}
}

// zypper exits 7 when another zypper or PackageKit holds the zypp lock, and
// prints no update. package.outdated read false for every package.
func TestPackageOutdatedFailedZypperCheck(t *testing.T) {
	withStructuredErrors(t, true)
	runtime := newSuseUpdateHost(t, "./packages/testdata/zypper-lu-locked-leap16.xml", 7)
	pkgs := listPackagesByName(t, runtime)

	outdated := pkgs["openssl"].GetOutdated()
	require.ErrorIs(t, outdated.Error, packages.ErrUpdateCheckFailed)
	assert.Contains(t, outdated.Error.Error(), "System management is locked")
}

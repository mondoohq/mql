// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
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
	case command == "command -v rpm":
		return out("/usr/bin/rpm\n", 0), nil
	case strings.HasPrefix(command, "rpm -qa"):
		return out(rpmUpdateHostList, 0), nil
	case strings.Contains(command, "check-update"):
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

func TestPkgUpdatesLookup(t *testing.T) {
	t.Run("joins on name and arch", func(t *testing.T) {
		pm := &fakeUpdatesPkgManager{updates: map[string]packages.PackageUpdate{
			"libc6": {Name: "libc6", Arch: "amd64", Available: "2.39-0ubuntu8.9"},
		}}
		u := &pkgUpdates{pm: pm}

		assert.Equal(t, "2.39-0ubuntu8.9", u.lookup("libc6", "amd64"))
		assert.Equal(t, "", u.lookup("libc6", "i386"), "an update for another arch is not this package's update")
		assert.Equal(t, 1, pm.calls)
	})

	// Managers with no update support (pacman, macOS, COS) return an error.
	// They keep reporting no newer version, as they did before.
	t.Run("a manager that cannot report updates reports no newer version", func(t *testing.T) {
		pm := &fakeUpdatesPkgManager{err: errors.New("Available() not implemented for pacman")}
		u := &pkgUpdates{pm: pm}
		assert.Equal(t, "", u.lookup("bash", "x86_64"))
		assert.Equal(t, "", u.lookup("openssl", "x86_64"))
		assert.Equal(t, 1, pm.calls, "a failed check is not retried per package")
	})
}

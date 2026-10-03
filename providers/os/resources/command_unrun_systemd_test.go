// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func fsConnWithFiles(t *testing.T, files map[string]string) *fs.FileSystemConnection {
	t.Helper()
	mfs := afero.NewMemMapFs()
	for p, content := range files {
		require.NoError(t, afero.WriteFile(mfs, p, []byte(content), 0o644))
	}
	conn, err := fs.NewFileSystemConnectionWithFs(1, &inventory.Config{}, &inventory.Asset{}, "/", nil, mfs)
	require.NoError(t, err)
	return conn
}

// noCommandRuntimeWithFiles is noCommandRuntime over the given files.
func noCommandRuntimeWithFiles(t *testing.T, files map[string]string) *plugin.Runtime {
	t.Helper()
	return testRuntime(t, fsConnWithFiles(t, files))
}

// failingCommandConn advertises command execution, like a local connection
// inside an image that ships no shell, and fails every command it is asked to
// run.
type failingCommandConn struct {
	*fs.FileSystemConnection
}

func (c *failingCommandConn) Capabilities() shared.Capabilities {
	return shared.Capability_File | shared.Capability_RunCommand
}

func (c *failingCommandConn) RunCommand(command string) (*shared.Command, error) {
	return nil, errExecNoShell
}

var errExecNoShell = &execError{"exec: \"sh\": executable file not found in $PATH"}

type execError struct{ msg string }

func (e *execError) Error() string { return e.msg }

func failingCommandRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	return testRuntime(t, &failingCommandConn{fsConnWithFiles(t, nil)})
}

// Before the fix, an fs or snapshot scan, and a local scan inside a shell-less
// image, read `systemctl is-active`'s errored exit code as 0 and reported both
// daemons as running.
func TestSystemdUnitActive_CommandCannotRun(t *testing.T) {
	for name, rt := range map[string]func(*testing.T) *plugin.Runtime{
		"no command execution": noCommandRuntime,
		"command fails to run": failingCommandRuntime,
	} {
		t.Run(name, func(t *testing.T) {
			resolved := mustResource(t, rt(t), "systemd.resolved").(*mqlSystemdResolved)
			v := resolved.GetActive()
			require.Error(t, v.Error)
			assert.False(t, v.Data)

			timesyncd := mustResource(t, rt(t), "systemd.timesyncd").(*mqlSystemdTimesyncd)
			v = timesyncd.GetActive()
			require.Error(t, v.Error)
			assert.False(t, v.Data)
			require.Error(t, timesyncd.GetSynchronized().Error)
		})
	}
}

// Without command execution resolved is never asked over D-Bus, so the
// settings come from resolved.conf alone, as for a daemon that is not running.
func TestSystemdResolved_ConfigWithoutCommands(t *testing.T) {
	rt := noCommandRuntimeWithFiles(t, map[string]string{
		"/etc/systemd/resolved.conf": "[Resolve]\nDNS=192.0.2.53\nDNSSEC=allow-downgrade\nCache=no\n",
	})
	r := mustResource(t, rt, "systemd.resolved").(*mqlSystemdResolved)

	cache := r.GetCache()
	require.NoError(t, cache.Error)
	assert.False(t, cache.Data)

	dns := r.GetDns()
	require.NoError(t, dns.Error)
	assert.Equal(t, []any{"192.0.2.53"}, dns.Data)

	dnssec := r.GetDnssec()
	require.NoError(t, dnssec.Error)
	assert.Equal(t, "allow-downgrade", dnssec.Data)

	cur := r.GetCurrentDnsServer()
	require.NoError(t, cur.Error)
	assert.Equal(t, "", cur.Data)
}

// A command that advertises execution but fails to run is not "resolved is
// stopped": nothing was measured, so the settings that depend on the live
// daemon error instead of falling back to the file.
func TestSystemdResolved_FailingCommandErrors(t *testing.T) {
	r := mustResource(t, failingCommandRuntime(t), "systemd.resolved").(*mqlSystemdResolved)
	require.Error(t, r.GetCache().Error)
}

// runShellCmd backs ovs and sriov. A command that never ran used to come back
// as a successful empty run: ovs reported itself installed and sriov reported
// no physical functions.
func TestRunShellCmd_CommandCannotRun(t *testing.T) {
	_, ok, err := runShellCmd(noCommandRuntime(t), "true")
	require.Error(t, err)
	assert.False(t, ok)

	sriov := mustResource(t, noCommandRuntime(t), "sriov").(*mqlSriov)
	require.Error(t, sriov.GetPhysicalFunctions().Error)

	ovs := mustResource(t, noCommandRuntime(t), "ovs").(*mqlOvs)
	require.Error(t, ovs.GetVersion().Error)

	// a command that ran and failed is still "not available", not an error
	rt := commandRuntime(t, map[string]*mock.Command{
		"false": {ExitStatus: 1},
	})
	out, ok, err := runShellCmd(rt, "false")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, "", out)
}

// nft --version on a connection whose commands fail to run must not cache an
// empty version as measured.
func TestNftablesVersion_CommandCannotRun(t *testing.T) {
	n := mustResource(t, failingCommandRuntime(t), "nftables").(*mqlNftables)
	_, err := n.fetchVersion()
	require.Error(t, err)
}

// pgrep that fails to run used to read as "listed, no postmasters", which
// skipped the /proc walk and lost every running cluster.
func TestRunningPostmasters_PgrepCannotRun(t *testing.T) {
	rt := testRuntime(t, &failingCommandConn{fsConnWithFiles(t, map[string]string{
		"/proc/4242/cmdline": "/usr/lib/postgresql/16/bin/postgres\x00-D\x00/var/lib/postgresql/16/main\x00",
	})})

	insts := runningPostmasters(rt)
	require.Len(t, insts, 1)
}

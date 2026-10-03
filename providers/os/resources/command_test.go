// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func testRuntime(t *testing.T, conn plugin.Connection) *plugin.Runtime {
	t.Helper()
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

// noCommandRuntime builds a runtime on a filesystem connection: it can read
// files but has no command execution, exactly like a container-image or
// mounted-volume scan. Every field of the `command` resource then carries
// plugin.ErrRunCommandNotImplemented with Data left at its zero value.
func noCommandRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	asset := &inventory.Asset{}
	conn, err := fs.NewFileSystemConnectionWithFs(1, &inventory.Config{}, asset, "/", nil, afero.NewMemMapFs())
	require.NoError(t, err)
	return testRuntime(t, conn)
}

// commandRuntime builds a runtime whose commands answer from the given table.
func commandRuntime(t *testing.T, cmds map[string]*mock.Command) *plugin.Runtime {
	t.Helper()
	for k, v := range cmds {
		v.Command = k
	}
	conn, err := mock.New(1, &inventory.Asset{}, mock.WithData(&mock.TomlData{Commands: cmds}))
	require.NoError(t, err)
	return testRuntime(t, conn)
}

func mustResource(t *testing.T, runtime *plugin.Runtime, name string) plugin.Resource {
	t.Helper()
	res, err := CreateResource(runtime, name, map[string]*llx.RawData{})
	require.NoError(t, err)
	return res
}

// TestCommandCannotRun_Errors pins the core contract: on a connection with no
// command execution, a resource that shells out must report an error. Before
// this was fixed every one of these read `exitcode` as 0 -- the zero value that
// accompanies the error -- parsed empty stdout, and answered with a confident
// zero value. macos.filevault/sip/gatekeeper each reported `enabled: false` on
// a Debian container image, which is a false-positive security finding on three
// of macOS's load-bearing controls.
func TestCommandCannotRun_Errors(t *testing.T) {
	t.Run("macos.filevault.enabled", func(t *testing.T) {
		r := mustResource(t, noCommandRuntime(t), "macos.filevault").(*mqlMacosFilevault)
		v := r.GetEnabled()
		require.Error(t, v.Error)
		assert.False(t, v.Data, "must not answer `false` when nothing was measured")
	})

	t.Run("macos.sip.enabled", func(t *testing.T) {
		r := mustResource(t, noCommandRuntime(t), "macos.sip").(*mqlMacosSip)
		v := r.GetEnabled()
		require.Error(t, v.Error)
		assert.False(t, v.Data)
	})

	t.Run("macos.gatekeeper.enabled", func(t *testing.T) {
		r := mustResource(t, noCommandRuntime(t), "macos.gatekeeper").(*mqlMacosGatekeeper)
		v := r.GetEnabled()
		require.Error(t, v.Error)
		assert.False(t, v.Data)
	})

	t.Run("macos.sharing", func(t *testing.T) {
		// A non-zero exit yields an empty panel, which sharingFlag answers
		// from each toggle's own setting; a command that never ran must not
		// take that path.
		r := mustResource(t, noCommandRuntime(t), "macos.sharing").(*mqlMacosSharing)
		state, err := r.fetchState()
		require.Error(t, err)
		assert.Nil(t, state)
	})

	t.Run("zfs.pools", func(t *testing.T) {
		r := mustResource(t, noCommandRuntime(t), "zfs").(*mqlZfs)
		v := r.GetPools()
		require.Error(t, v.Error)
		assert.Empty(t, v.Data)
	})

	t.Run("mdadm.arrays", func(t *testing.T) {
		// This one used to return an empty list on any failure, so an image
		// scan reported "no RAID arrays" as a measured fact.
		r := mustResource(t, noCommandRuntime(t), "mdadm").(*mqlMdadm)
		require.Error(t, r.GetArrays().Error)
	})

	// lsblk and lvm must fail on the command itself, not on a JSON parser
	// rejecting empty stdout: a parser that grows tolerant of empty input
	// would otherwise turn them into silent empty lists.
	t.Run("lsblk.list", func(t *testing.T) {
		r := mustResource(t, noCommandRuntime(t), "lsblk").(*mqlLsblk)
		err := r.GetList().Error
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot run commands")
	})

	t.Run("lvm.volumeGroups", func(t *testing.T) {
		r := mustResource(t, noCommandRuntime(t), "lvm").(*mqlLvm)
		err := r.GetVolumeGroups().Error
		require.Error(t, err)
		assert.ErrorIs(t, err, plugin.ErrRunCommandNotImplemented)
	})

	t.Run("mount df entries", func(t *testing.T) {
		// mount.point size/used/available come from `df`, which used to fall
		// back to an empty table whenever the command "failed".
		r := mustResource(t, noCommandRuntime(t), "mount").(*mqlMount)
		_, err := r.fetchDfEntries()
		require.Error(t, err)
	})
}

// TestCommandExitsNonZero_Unchanged pins that a command which really ran and
// really failed keeps its old behaviour: an error naming the command and
// carrying its stderr.
func TestCommandExitsNonZero_Unchanged(t *testing.T) {
	t.Run("macos.filevault.enabled", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"fdesetup status": {Stderr: "not permitted", ExitStatus: 1},
		})
		v := mustResource(t, rt, "macos.filevault").(*mqlMacosFilevault).GetEnabled()
		require.Error(t, v.Error)
		assert.Contains(t, v.Error.Error(), "fdesetup status failed: not permitted")
	})

	t.Run("diagnostic on stdout only", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"csrutil status": {Stdout: "csrutil: this tool needs to be executed from Recovery OS\n", ExitStatus: 1},
		})
		v := mustResource(t, rt, "macos.sip").(*mqlMacosSip).GetEnabled()
		require.Error(t, v.Error)
		assert.Contains(t, v.Error.Error(), "csrutil status failed: csrutil: this tool needs to be executed from Recovery OS")
	})

	t.Run("zfs.pools", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"zpool get -jp all": {Stderr: "internal error: failed to initialize ZFS library", ExitStatus: 1},
		})
		v := mustResource(t, rt, "zfs").(*mqlZfs).GetPools()
		require.Error(t, v.Error)
		assert.Contains(t, v.Error.Error(), "failed to initialize ZFS library")
	})
}

// TestCommandSucceeds_Unchanged pins that a command which ran and exited zero
// still produces the value it always did.
func TestCommandSucceeds_Unchanged(t *testing.T) {
	t.Run("filevault on", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"fdesetup status": {Stdout: "FileVault is On.\n"},
		})
		r := mustResource(t, rt, "macos.filevault").(*mqlMacosFilevault)
		v := r.GetEnabled()
		require.NoError(t, v.Error)
		assert.True(t, v.Data)
		assert.Equal(t, "FileVault is On.", r.GetStatus().Data)
	})

	t.Run("filevault off", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"fdesetup status": {Stdout: "FileVault is Off.\n"},
		})
		v := mustResource(t, rt, "macos.filevault").(*mqlMacosFilevault).GetEnabled()
		require.NoError(t, v.Error)
		assert.False(t, v.Data, "a measured `false` is still a measured `false`")
	})

	t.Run("gatekeeper enabled", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"spctl --status": {Stdout: "assessments enabled\n"},
		})
		v := mustResource(t, rt, "macos.gatekeeper").(*mqlMacosGatekeeper).GetEnabled()
		require.NoError(t, v.Error)
		assert.True(t, v.Data)
	})

	t.Run("sip enabled", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"csrutil status": {Stdout: "System Integrity Protection status: enabled.\n"},
		})
		v := mustResource(t, rt, "macos.sip").(*mqlMacosSip).GetEnabled()
		require.NoError(t, v.Error)
		assert.True(t, v.Data)
	})
}

// TestDeliberateNonZeroExitBranchesSurvive guards the branches that act on a
// specific non-zero exit code. Routing every site through a "non-zero means
// error" helper would have flattened these.
func TestDeliberateNonZeroExitBranchesSurvive(t *testing.T) {
	t.Run("lvm exit 127 means not installed, not an error", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{})
		lvm := mustResource(t, rt, "lvm").(*mqlLvm)
		// the mock answers an unknown command with exit 1 + "command not
		// found: ...", which isLvmNotInstalled also accepts; pin the 127 path
		// through the helper directly so the exit code itself is the input.
		out, ok, err := lvm.runLvmReport("vgs", "vg", "vg_name")
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Empty(t, out)

		rt = commandRuntime(t, map[string]*mock.Command{
			"vgs --reportformat json --units b --nosuffix -o vg_name": {ExitStatus: 127},
		})
		lvm = mustResource(t, rt, "lvm").(*mqlLvm)
		out, ok, err = lvm.runLvmReport("vgs", "vg", "vg_name")
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Empty(t, out)
	})

	t.Run("lvm other non-zero exit is still an error", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"vgs --reportformat json --units b --nosuffix -o vg_name": {ExitStatus: 5, Stderr: "broken metadata"},
		})
		lvm := mustResource(t, rt, "lvm").(*mqlLvm)
		_, _, err := lvm.runLvmReport("vgs", "vg", "vg_name")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exit 5")
	})

	t.Run("macos.sharing non-zero exit yields an empty panel", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			systemProfilerSharingCmd: {ExitStatus: 1},
		})
		r := mustResource(t, rt, "macos.sharing").(*mqlMacosSharing)
		state, err := r.fetchState()
		require.NoError(t, err)
		assert.Empty(t, state)
	})

	t.Run("systemctl non-zero exit means inactive, not an error", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"systemctl is-active -- systemd-resolved.service": {ExitStatus: 3, Stdout: "inactive\n"},
		})
		active, err := isSystemdUnitActive(rt, "systemd-resolved.service")
		require.NoError(t, err)
		assert.False(t, active)
	})
}

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

// Without command execution resolved is never asked over D-Bus, so the

// settings come from resolved.conf alone, as for a daemon that is not running.

// A command that advertises execution but fails to run is not "resolved is

// stopped": nothing was measured, so the settings that depend on the live

// daemon error instead of falling back to the file.

// runShellCmd backs ovs and sriov. A command that never ran used to come back

// as a successful empty run: ovs reported itself installed and sriov reported

// no physical functions.

// A list accessor cannot express "unknown" by returning a nil slice: the
// runtime writes StateIsSet with no StateIsNull, and TValue.ToDataRes then
// serializes the nil slice as an empty array. Both `return nil, nil` and
// `return []any{}, nil` reach the client as `[]`.
//
// That matters because for list assertions EMPTY is the unsafe state, not null.
// `.none(...)` and `.all(...)` over an empty list are vacuously TRUE, so a host
// where `semodule -l` or `mdadm --detail --scan` could not run used to PASS
// every assertion over data nobody read. A null list fails those same
// assertions.
//
// So each accessor below has to separate two cases that look identical in the
// return value:
//
//   - we could not read      -> StateIsSet|StateIsNull, fails closed
//   - we read, found nothing -> an empty list, a measured fact
//
// These tests pin both directions. Getting either one backwards is a bug.

func TestUnreadListIsNull(t *testing.T) {
	t.Run("mdadm.arrays: scan could not run", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"mdadm --detail --scan": {ExitStatus: 1, Stderr: "mdadm: not found"},
		})
		v := mustResource(t, rt, "mdadm").(*mqlMdadm).GetArrays()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull(), "a failed scan must not read as `no arrays`")
	})

	t.Run("mdadm.arrays: scan listed arrays but none could be read", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"mdadm --detail --scan":     {Stdout: "ARRAY /dev/md0 metadata=1.2 UUID=abc\n"},
			`mdadm --detail "/dev/md0"`: {ExitStatus: 1, Stderr: "permission denied"},
		})
		v := mustResource(t, rt, "mdadm").(*mqlMdadm).GetArrays()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull(), "the scan found an array, so `no arrays` is false")
	})

	t.Run("selinux.modules: semodule could not run", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			semoduleListCmd: {ExitStatus: 127, Stderr: "semodule: command not found"},
		})
		v := mustResource(t, rt, "selinux").(*mqlSelinux).GetModules()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull())
	})

	t.Run("selinux.modules: no command execution", func(t *testing.T) {
		v := mustResource(t, noCommandRuntime(t), "selinux").(*mqlSelinux).GetModules()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull(), "an image scan never ran semodule")
	})

	t.Run("selinux.booleans: no source answered", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"getsebool -a": {ExitStatus: 127, Stderr: "getsebool: command not found"},
		})
		v := mustResource(t, rt, "selinux").(*mqlSelinux).GetBooleans()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull())
	})

	t.Run("firewalld.zones: daemon not running", func(t *testing.T) {
		// firewall-cmd can only enumerate zones through a running daemon, so a
		// stopped firewalld leaves the zone set unread rather than empty.
		rt := commandRuntime(t, map[string]*mock.Command{
			"firewall-cmd --state": {ExitStatus: 252, Stderr: "not running"},
		})
		f := mustResource(t, rt, "firewalld").(*mqlFirewalld)
		require.Equal(t, "not running", f.GetStatus().Data)
		v := f.GetZones()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull())
	})

	t.Run("containerd.containers: every namespace refused", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"ctr namespaces list -q":            {Stdout: "default\n"},
			"ctr -n default containers list -q": {ExitStatus: 1, Stderr: "permission denied"},
		})
		v := mustResource(t, rt, "containerd").(*mqlContainerd).GetContainers()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull(), "we listed no containers because we were refused, not because there are none")
	})
}

func TestMeasuredEmptyListStaysEmpty(t *testing.T) {
	t.Run("mdadm.arrays: scan ran and listed nothing", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"mdadm --detail --scan": {Stdout: ""},
		})
		v := mustResource(t, rt, "mdadm").(*mqlMdadm).GetArrays()
		require.NoError(t, v.Error)
		assert.False(t, v.IsNull(), "exit 0 with no ARRAY lines is a measured `no arrays`")
		assert.Empty(t, v.Data)
	})

	t.Run("selinux.modules: semodule ran and listed nothing", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			semoduleListCmd: {Stdout: "\n"},
		})
		v := mustResource(t, rt, "selinux").(*mqlSelinux).GetModules()
		require.NoError(t, v.Error)
		assert.False(t, v.IsNull())
		assert.Empty(t, v.Data)
	})

	t.Run("containerd.containers: no namespaces", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"ctr namespaces list -q": {Stdout: ""},
		})
		v := mustResource(t, rt, "containerd").(*mqlContainerd).GetContainers()
		require.NoError(t, v.Error)
		assert.False(t, v.IsNull())
		assert.Empty(t, v.Data)
	})
}

func TestReadListIsPopulated(t *testing.T) {
	t.Run("mdadm.arrays", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"mdadm --detail --scan": {Stdout: "ARRAY /dev/md0 metadata=1.2 UUID=abc\n"},
			`mdadm --detail "/dev/md0"`: {Stdout: "" +
				"/dev/md0:\n" +
				"     Raid Level : raid1\n" +
				"          State : clean\n" +
				" Active Devices : 2\n"},
		})
		v := mustResource(t, rt, "mdadm").(*mqlMdadm).GetArrays()
		require.NoError(t, v.Error)
		require.False(t, v.IsNull())
		require.Len(t, v.Data, 1)
		arr := v.Data[0].(*mqlMdadmArray)
		assert.Equal(t, "/dev/md0", arr.Name.Data)
		assert.Equal(t, "raid1", arr.Level.Data)
		assert.Equal(t, "clean", arr.State.Data)
	})

	t.Run("selinux.modules", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			semoduleListCmd: {Stdout: "100 zebra enabled\n200 apache disabled\n"},
		})
		v := mustResource(t, rt, "selinux").(*mqlSelinux).GetModules()
		require.NoError(t, v.Error)
		require.False(t, v.IsNull())
		require.Len(t, v.Data, 2)
		assert.Equal(t, "zebra", v.Data[0].(*mqlSelinuxModule).Name.Data)
		assert.Equal(t, "disabled", v.Data[1].(*mqlSelinuxModule).Status.Data)
	})

	t.Run("selinux.booleans", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"getsebool -a": {Stdout: "httpd_can_network_connect --> on\nhttpd_enable_cgi --> off\n"},
		})
		v := mustResource(t, rt, "selinux").(*mqlSelinux).GetBooleans()
		require.NoError(t, v.Error)
		require.False(t, v.IsNull())
		require.Len(t, v.Data, 2)
		assert.True(t, v.Data[0].(*mqlSelinuxBoolean).Value.Data)
		assert.False(t, v.Data[1].(*mqlSelinuxBoolean).Value.Data)
	})
}

// A read the target refused is an error, never a null (ADR 046 §3). Under
// structured errors a denied mdadm or semodule run is forbidden; without them
// it stays the unknown null above.
func TestRefusedListIsForbidden(t *testing.T) {
	t.Run("mdadm.arrays: scan refused", func(t *testing.T) {
		withStructuredErrors(t, true)
		rt := commandRuntime(t, map[string]*mock.Command{
			"mdadm --detail --scan": {ExitStatus: 1, Stderr: "mdadm: cannot open /dev/md0: Permission denied\n"},
		})
		v := mustResource(t, rt, "mdadm").(*mqlMdadm).GetArrays()
		assert.True(t, errors.Is(v.Error, llx.ErrForbidden), "got %v", v.Error)
	})

	t.Run("mdadm.arrays: scan not installed stays null", func(t *testing.T) {
		withStructuredErrors(t, true)
		rt := commandRuntime(t, map[string]*mock.Command{
			"mdadm --detail --scan": {ExitStatus: 127, Stderr: "mdadm: not found"},
		})
		v := mustResource(t, rt, "mdadm").(*mqlMdadm).GetArrays()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull())
	})

	t.Run("mdadm.arrays: every detail refused", func(t *testing.T) {
		withStructuredErrors(t, true)
		rt := commandRuntime(t, map[string]*mock.Command{
			"mdadm --detail --scan":     {Stdout: "ARRAY /dev/md0 metadata=1.2 UUID=abc\n"},
			`mdadm --detail "/dev/md0"`: {ExitStatus: 1, Stderr: "mdadm: cannot open /dev/md0: Permission denied\n"},
		})
		v := mustResource(t, rt, "mdadm").(*mqlMdadm).GetArrays()
		assert.True(t, errors.Is(v.Error, llx.ErrForbidden), "got %v", v.Error)
	})

	t.Run("mdadm.arrays: every detail refused, v13", func(t *testing.T) {
		withStructuredErrors(t, false)
		rt := commandRuntime(t, map[string]*mock.Command{
			"mdadm --detail --scan":     {Stdout: "ARRAY /dev/md0 metadata=1.2 UUID=abc\n"},
			`mdadm --detail "/dev/md0"`: {ExitStatus: 1, Stderr: "mdadm: cannot open /dev/md0: Permission denied\n"},
		})
		v := mustResource(t, rt, "mdadm").(*mqlMdadm).GetArrays()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull())
	})

	t.Run("selinux.modules: semodule refused", func(t *testing.T) {
		withStructuredErrors(t, true)
		rt := commandRuntime(t, map[string]*mock.Command{
			semoduleListCmd: {ExitStatus: 1, Stderr: "libsemanage.semanage_create_store: Could not read from module store, active modules subdirectory at /var/lib/selinux/targeted/active/modules. (Permission denied).\n"},
		})
		v := mustResource(t, rt, "selinux").(*mqlSelinux).GetModules()
		assert.True(t, errors.Is(v.Error, llx.ErrForbidden), "got %v", v.Error)
	})
}

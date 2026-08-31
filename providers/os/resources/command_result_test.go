// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/providers/os/connection/mock"
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
		// A non-zero exit legitimately means "this release has no Sharing
		// panel" and yields an empty map; a command that never ran must not
		// take that path.
		r := mustResource(t, noCommandRuntime(t), "macos.sharing").(*mqlMacosSharing)
		_, err := r.fetchState()
		require.Error(t, err)
		assert.NotErrorIs(t, err, errSharingPanelUnavailable)
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

	// lsblk and lvm already surfaced a failure before the fix, but only by
	// accident: they fed the empty stdout to a JSON parser that rejected it.
	// These pin the error to the command, so a parser that grows tolerant of
	// empty input cannot turn them into silent empty lists.
	t.Run("lsblk.list", func(t *testing.T) {
		r := mustResource(t, noCommandRuntime(t), "lsblk").(*mqlLsblk)
		err := r.GetList().Error
		require.Error(t, err)
		assert.ErrorIs(t, err, plugin.ErrRunCommandNotImplemented)
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

	t.Run("zfs.pools", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"zpool get -jp all": {Stderr: "zpool: not found", ExitStatus: 127},
		})
		v := mustResource(t, rt, "zfs").(*mqlZfs).GetPools()
		require.Error(t, v.Error)
		assert.Contains(t, v.Error.Error(), "zpool: not found")
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
		out, ok, err := lvm.runLvmReport("vgs --reportformat json")
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Empty(t, out)

		rt = commandRuntime(t, map[string]*mock.Command{
			"vgs --reportformat json": {ExitStatus: 127},
		})
		lvm = mustResource(t, rt, "lvm").(*mqlLvm)
		out, ok, err = lvm.runLvmReport("vgs --reportformat json")
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Empty(t, out)
	})

	t.Run("lvm other non-zero exit is still an error", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"vgs --reportformat json": {ExitStatus: 5, Stderr: "broken metadata"},
		})
		lvm := mustResource(t, rt, "lvm").(*mqlLvm)
		_, _, err := lvm.runLvmReport("vgs --reportformat json")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exit 5")
	})

	t.Run("mdadm non-zero exit means no arrays", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"mdadm --detail --scan": {ExitStatus: 1, Stderr: "mdadm: not found"},
		})
		v := mustResource(t, rt, "mdadm").(*mqlMdadm).GetArrays()
		require.NoError(t, v.Error)
		assert.Empty(t, v.Data)
	})

	t.Run("macos.sharing non-zero exit yields an empty panel", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			systemProfilerSharingCmd: {ExitStatus: 1},
		})
		r := mustResource(t, rt, "macos.sharing").(*mqlMacosSharing)
		state, err := r.fetchState()
		require.NoError(t, err)
		assert.Empty(t, state)
		// and an empty panel is still reported as "not measured", not "off"
		assert.ErrorIs(t, r.GetFileSharing().Error, errSharingPanelUnavailable)
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

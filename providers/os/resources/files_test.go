// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/filesfind"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/utils/syncx"
)

// filesFindWithCmdResult wires a files.find resource to a mock connection that
// answers the exact `find` invocation the resource builds with the given
// stdout / stderr / exit status.
func filesFindWithCmdResult(t *testing.T, from string, fileType string, stdout string, stderr string, exitStatus int) *mqlFilesFind {
	t.Helper()

	cmdline := filesfind.BuildFilesFindCmd(from, false, fileType, "", 0o777, "", nil, true)

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "arch",
			Family: []string{"linux", "unix"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			cmdline: {
				Command:    cmdline,
				Stdout:     stdout,
				Stderr:     stderr,
				ExitStatus: exitStatus,
			},
		},
	}))
	require.NoError(t, err)

	res := &mqlFilesFind{}
	res.MqlRuntime = &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
	res.From = plugin.TValue[string]{Data: from, State: plugin.StateIsSet}
	res.Type = plugin.TValue[string]{Data: fileType, State: plugin.StateIsSet}
	res.Permissions = plugin.TValue[int64]{Data: 0o777, State: plugin.StateIsSet}
	return res
}

// A host without findutils (amazonlinux 2023, opencloudos, openEuler) exits
// 127 with nothing on stdout. Reporting that as "no files matched" makes every
// resource built on files.find — logrotate, sudoers, limits, modprobe, apt and
// the rest — silently under-report.
func TestFilesFind_UnixCmd_FailedCommandIsAnError(t *testing.T) {
	res := filesFindWithCmdResult(t, "/etc", "file", "", "sh: find: command not found", 127)

	found, err := res.unixFilesFindCmd()
	require.Error(t, err)
	assert.Empty(t, found)
	assert.Contains(t, err.Error(), "127")
	assert.Contains(t, err.Error(), "find: command not found")
}

// GNU find exits 1 when it cannot descend into a subdirectory while still
// printing every path it did reach. That is routine for an unprivileged scan
// of /etc and must keep returning results.
func TestFilesFind_UnixCmd_PartialTraversalKeepsResults(t *testing.T) {
	res := filesFindWithCmdResult(t, "/etc", "file",
		"/etc/hosts\n/etc/passwd\n",
		"find: '/etc/ssl/private': Permission denied", 1)

	found, err := res.unixFilesFindCmd()
	require.NoError(t, err)
	assert.Equal(t, []string{"/etc/hosts", "/etc/passwd"}, found)
}

// An empty directory is not a failure: exit 0 with no output is an honest
// "nothing matched".
func TestFilesFind_UnixCmd_EmptyResultIsNotAnError(t *testing.T) {
	res := filesFindWithCmdResult(t, "/etc", "file", "", "", 0)

	found, err := res.unixFilesFindCmd()
	require.NoError(t, err)
	assert.Empty(t, found)
}

// The Windows path has the same shape: a PowerShell run that never produced a
// listing must not read as an empty directory.
func TestFilesFind_Powershell_FailedScriptIsAnError(t *testing.T) {
	script := filesfind.BuildPowershellCmd("C:\\Windows", false, "file", "", 0o777, "", nil)
	// the powershell resource base64-encodes the script before running it
	encoded := powershell.Encode(script)

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "windows",
			Family: []string{"windows"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			encoded: {
				Command:    encoded,
				Stderr:     "The system cannot find the path specified.",
				ExitStatus: 1,
			},
		},
	}))
	require.NoError(t, err)

	res := &mqlFilesFind{}
	res.MqlRuntime = &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
	res.From = plugin.TValue[string]{Data: "C:\\Windows", State: plugin.StateIsSet}
	res.Type = plugin.TValue[string]{Data: "file", State: plugin.StateIsSet}
	res.Permissions = plugin.TValue[int64]{Data: 0o777, State: plugin.StateIsSet}

	found, err := res.windowsPowershellCmd()
	require.Error(t, err)
	assert.Empty(t, found)
	assert.Contains(t, err.Error(), "cannot find the path")
}

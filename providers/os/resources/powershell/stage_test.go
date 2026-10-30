// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package powershell_test

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// readOnlyFs is the shape both cat.Fs shims have: it advertises a filesystem
// and refuses every mutating call. winrm and `ssh --sudo` both hand one of
// these back, which is the reason the chunked fallback exists at all.
type readOnlyFs struct{ afero.Fs }

func (readOnlyFs) Create(string) (afero.File, error) {
	return nil, errors.New("not implemented")
}

func (readOnlyFs) OpenFile(string, int, os.FileMode) (afero.File, error) {
	return nil, errors.New("not implemented")
}

type fakeConn struct {
	connType shared.ConnectionType
	platform *inventory.Platform
	fs       afero.Fs
	caps     shared.Capabilities
	// commands records every RunCommand in order, which is what the chunked
	// write has to be asserted on: the file never exists locally.
	commands []string
	exit     int
}

func (c *fakeConn) ID() uint32                        { return 1 }
func (c *fakeConn) Name() string                      { return "fake" }
func (c *fakeConn) Type() shared.ConnectionType       { return c.connType }
func (c *fakeConn) Capabilities() shared.Capabilities { return c.caps }
func (c *fakeConn) UpdateAsset(a *inventory.Asset)    {}
func (c *fakeConn) ParentID() uint32                  { return 0 }
func (c *fakeConn) SetParentID(uint32)                {}
func (c *fakeConn) Asset() *inventory.Asset {
	return &inventory.Asset{Platform: c.platform}
}
func (c *fakeConn) FileSystem() afero.Fs { return c.fs }
func (c *fakeConn) FileInfo(string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, errors.New("not implemented")
}
func (c *fakeConn) RunCommand(cmd string) (*shared.Command, error) {
	c.commands = append(c.commands, cmd)
	return &shared.Command{
		Command: cmd, ExitStatus: c.exit,
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	}, nil
}

var _ shared.Connection = (*fakeConn)(nil)
var _ plugin.Connection = (*fakeConn)(nil)

func windowsPlatform() *inventory.Platform {
	return &inventory.Platform{Name: "windows", Family: []string{"windows", "os"}}
}

// The hash is what keeps two staged scripts from colliding under one recording
// key, so it has to depend on the content and on nothing else.
func TestStagedNameIsContentAddressed(t *testing.T) {
	a := powershell.StagedName("iis", "Get-Item A")
	b := powershell.StagedName("iis", "Get-Item B")
	assert.NotEqual(t, a, b, "two different scripts must not stage to one path")
	assert.Equal(t, a, powershell.StagedName("iis", "Get-Item A"),
		"the same script must stage to the same path on every run")
	assert.True(t, strings.HasPrefix(a, "iis-") && strings.HasSuffix(a, ".ps1"), a)
}

// -File is execution-policy sensitive where -EncodedCommand is not, and the
// RemoteSigned default hides that. Losing the Bypass would leave a resource
// that works everywhere except on a hardened host.
func TestStagedCommandBypassesTheExecutionPolicy(t *testing.T) {
	cmd := powershell.StagedCommand(`C:\Windows\Temp\iis-abc.ps1`)
	assert.Contains(t, cmd, "-ExecutionPolicy Bypass")
	assert.Contains(t, cmd, "-File")
	assert.NotContains(t, cmd, "-EncodedCommand")
}

// The staged directory must come from the client's view of the asset, never
// from the target. A `$env:TEMP` round trip would put a host-dependent string
// into the command that keys the recording, and replay would stop matching.
func TestStagedPathIsAClientSideLiteral(t *testing.T) {
	conn := &fakeConn{
		connType: "mock", platform: windowsPlatform(),
		caps: shared.Capability_RunCommand,
	}
	staged, err := powershell.Stage(conn, "iis", "Get-Item C:\\; ConvertTo-Json @{}")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(staged.Path, `C:\Windows\Temp\`), staged.Path)
	assert.Empty(t, conn.commands, "a mock connection must not be written to")

	// And the same script, on a second connection to a different host, must
	// produce byte-identical commands — that is the replay guarantee.
	other := &fakeConn{
		connType: "mock", platform: windowsPlatform(),
		caps: shared.Capability_RunCommand,
	}
	again, err := powershell.Stage(other, "iis", "Get-Item C:\\; ConvertTo-Json @{}")
	require.NoError(t, err)
	assert.Equal(t, staged.Command, again.Command)
}

func TestStageWritesThroughAWritableFilesystem(t *testing.T) {
	fs := afero.NewMemMapFs()
	conn := &fakeConn{
		connType: shared.Type_SSH, platform: windowsPlatform(),
		fs: fs, caps: shared.Capability_RunCommand | shared.Capability_File,
	}
	script := "$ErrorActionPreference = 'Stop'\nConvertTo-Json @{ a = 1 }\n"
	staged, err := powershell.Stage(conn, "iis", script)
	require.NoError(t, err)

	body, err := afero.ReadFile(fs, staged.Path)
	require.NoError(t, err)
	assert.Equal(t, script, string(body))
	assert.Empty(t, conn.commands, "the filesystem path must not shell out")

	// The script went on through the filesystem, so the cleanup goes back through
	// it. Launching powershell.exe to delete a file the connection can unlink
	// itself costs a whole process start on the target for nothing.
	staged.Remove()
	assert.Empty(t, conn.commands, "the filesystem path must not shell out to clean up")
	left, err := afero.Exists(fs, staged.Path)
	require.NoError(t, err)
	assert.False(t, left, "the staged script was left on the target")
}

// winrm and `ssh --sudo`: the filesystem is there and refuses to write, so the
// script has to go over RunCommand in pieces. The assertion that matters is
// that no single command approaches the 8191 ceiling — the whole point is that
// the script is longer than one.
func TestStageFallsBackToChunkedCommandsOnAReadOnlyFilesystem(t *testing.T) {
	conn := &fakeConn{
		connType: shared.Type_Winrm, platform: windowsPlatform(),
		fs:   readOnlyFs{afero.NewMemMapFs()},
		caps: shared.Capability_RunCommand | shared.Capability_File,
	}
	// Comfortably past the cap, and past one chunk.
	script := "$ErrorActionPreference = 'Stop'\n" + strings.Repeat("# padding line\n", 1200)
	require.Greater(t, len(powershell.Encode(script)), powershell.MaxCommandLength,
		"the fixture script has to be over the cap or this proves nothing")

	staged, err := powershell.Stage(conn, "iis", script)
	require.NoError(t, err)
	require.Greater(t, len(conn.commands), 2, "expected a clear, several chunks and a decode")

	for i, cmd := range conn.commands {
		assert.LessOrEqual(t, len(cmd), powershell.MaxCommandLength,
			"staging command %d is %d chars, which is over the very ceiling "+
				"staging exists to avoid", i, len(cmd))
	}
	assert.Contains(t, conn.commands[0], "Remove-Item")
	assert.Contains(t, conn.commands[len(conn.commands)-1], "FromBase64String")
	assert.Contains(t, staged.Command, staged.Path)

	assertStagingCommandShape(t, conn.commands)
}

// assertStagingCommandShape pins the two properties every staging command needs,
// both of which were established by a command that failed on a live host.
func assertStagingCommandShape(t *testing.T, commands []string) {
	t.Helper()
	for i, cmd := range commands {
		// 1. The exit code is computed, not inherited. `powershell -Command`
		// exits 1 whenever $? is false at the end, and $? is false after a
		// *suppressed* error too — so `Remove-Item -ErrorAction SilentlyContinue`
		// on a file that is not there exits 1 with empty stderr. Read at face
		// value that aborts a scan that would have worked.
		assert.Contains(t, cmd, "exit 0", "staging command %d does not set its own exit code", i)
		assert.Contains(t, cmd, "exit 1", "staging command %d has no failure exit", i)

		// 2. No `$`, anywhere. Over SSH to a Windows host whose sshd
		// DefaultShell is PowerShell — the normal configuration — the command
		// line is parsed twice, and the outer pass expands any variable inside
		// the double-quoted argument before the inner powershell.exe sees it.
		// `$ErrorActionPreference='Stop'` becomes `='Stop'`, which is a syntax
		// error, and on the cleanup path that failure is silent: the staged file
		// is simply left on the target after every scan.
		assert.NotContains(t, cmd, "$",
			"staging command %d contains a variable, which an outer PowerShell "+
				"login shell will expand before powershell.exe sees it", i)
	}
}

// A write that fails has to be reported. RunCommand reports a failed *command*
// through ExitStatus and not through err, so a helper that only checks err
// stages nothing and says it succeeded — and the caller then runs a -File that
// is not there.
func TestStageReportsANonZeroExitFromTheWrite(t *testing.T) {
	conn := &fakeConn{
		connType: shared.Type_Winrm, platform: windowsPlatform(),
		fs:   readOnlyFs{afero.NewMemMapFs()},
		caps: shared.Capability_RunCommand | shared.Capability_File,
		exit: 1,
	}
	_, err := powershell.Stage(conn, "iis", "ConvertTo-Json @{ a = 1 }\n"+strings.Repeat("#x\n", 50))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exited 1")
}

func TestCanStage(t *testing.T) {
	assert.False(t, powershell.CanStage(nil))
	assert.True(t, powershell.CanStage(&fakeConn{
		connType: "mock", platform: windowsPlatform(), caps: shared.Capability_None}))
	assert.False(t, powershell.CanStage(&fakeConn{
		connType: shared.Type_ContainerRegistry, platform: windowsPlatform(),
		caps: shared.Capability_File}),
		"Capability_File alone is a read-only shim, which cannot be staged to")
}

// StagedWindowsPath is what a test derives a recording key from, so it has to
// agree with what Stage actually produces on a Windows asset. If they drift, a
// resource test builds a recording under a key the resource never asks for and
// fails with "command not found" — which reads as a broken resource.
func TestStagedWindowsPathMatchesStage(t *testing.T) {
	script := "$ErrorActionPreference = 'Stop'\nConvertTo-Json @{ a = 1 }\n"
	conn := &fakeConn{
		connType: "mock", platform: windowsPlatform(),
		caps: shared.Capability_RunCommand,
	}
	staged, err := powershell.Stage(conn, "iis", script)
	require.NoError(t, err)
	assert.Equal(t, staged.Path, powershell.StagedWindowsPath("iis", script))
	assert.Equal(t, staged.Command,
		powershell.StagedCommand(powershell.StagedWindowsPath("iis", script)))
}

// The staging directory is writable by every local user and the file name is
// derived from the script, so the path can be occupied before a scan starts.
// Staging must create its own file rather than write through one that is
// already there.
func TestStageWillNotWriteThroughAnExistingFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	script := "ConvertTo-Json @{ a = 1 }\n"
	path := powershell.StagedWindowsPath("iis", script)
	require.NoError(t, afero.WriteFile(fs, path, []byte("planted"), 0o644))

	// no RunCommand fallback available, so a refused write is the whole result
	conn := &fakeConn{
		connType: shared.Type_SSH, platform: windowsPlatform(),
		fs: undeletableFs{fs}, caps: shared.Capability_File,
	}

	_, err := powershell.Stage(conn, "iis", script)
	require.Error(t, err)

	body, readErr := afero.ReadFile(fs, path)
	require.NoError(t, readErr)
	assert.Equal(t, "planted", string(body), "staging overwrote a file it did not create")
}

// undeletableFs stands in for a file the scanner is not permitted to delete:
// a write may succeed, the removal never does.
type undeletableFs struct{ afero.Fs }

func (undeletableFs) Remove(string) error { return errors.New("permission denied") }

// countingFs records the calls staging makes on the filesystem. It is the only
// way to observe a round trip that is *not* there: over sftp every Remove is a
// request to the target, and on the common path there is nothing to delete.
type countingFs struct {
	afero.Fs
	removes int
}

func (c *countingFs) Remove(name string) error {
	c.removes++
	return c.Fs.Remove(name)
}

// The chunked write is the path every read-only connection takes, so it needs
// the same guarantee: create the file, do not adopt one.
func TestChunkedStagingCreatesItsOwnFiles(t *testing.T) {
	conn := &fakeConn{
		connType: shared.Type_Winrm, platform: windowsPlatform(),
		fs:   readOnlyFs{afero.NewMemMapFs()},
		caps: shared.Capability_RunCommand | shared.Capability_File,
	}
	_, err := powershell.Stage(conn, "iis", "ConvertTo-Json @{ a = 1 }\n"+strings.Repeat("#x\n", 50))
	require.NoError(t, err)
	require.Greater(t, len(conn.commands), 2)

	first := conn.commands[0]
	last := conn.commands[len(conn.commands)-1]

	// New-Item without -Force fails on an existing item, which is the
	// exclusive create; -Force would silently reuse whatever is there. The
	// path sits between -Path and any -Force, so the two have to be checked
	// per statement rather than as one substring.
	for _, cmd := range []string{first, last} {
		creates := 0
		for stmt := range strings.SplitSeq(cmd, ";") {
			if !strings.Contains(stmt, "New-Item") {
				continue
			}
			creates++
			assert.NotContains(t, stmt, "-Force",
				"New-Item has to fail on an existing item, so it cannot take -Force: %s", stmt)
		}
		assert.Equal(t, 1, creates, "expected one exclusive create in %q", cmd)
	}

	// 0x400 is FILE_ATTRIBUTE_REPARSE_POINT: a link at the path would send the
	// payload somewhere else
	assert.Contains(t, first, "-band 1024")

	assertStagingCommandShape(t, conn.commands)
}

// The staging path is free on every scan that cleaned up after itself, which is
// every scan that was not interrupted. Deleting it first spends a round trip -
// two, over sftp, where Remove tries the file and then the directory - to
// delete nothing. Create first, and clear only when the create says something
// is in the way.
func TestStageDoesNotDeleteAPathThatIsFree(t *testing.T) {
	fs := &countingFs{Fs: afero.NewMemMapFs()}
	conn := &fakeConn{
		connType: shared.Type_SSH, platform: windowsPlatform(),
		fs: fs, caps: shared.Capability_RunCommand | shared.Capability_File,
	}

	script := "ConvertTo-Json @{ a = 1 }\n"
	staged, err := powershell.Stage(conn, "iis", script)
	require.NoError(t, err)
	assert.Zero(t, fs.removes, "staging deleted a file that was not there")

	body, err := afero.ReadFile(fs, staged.Path)
	require.NoError(t, err)
	assert.Equal(t, script, string(body))
}

// A scan that died between the write and the run leaves its file behind. The
// next one has to clear it rather than degrade to the chunked write, and what
// it runs has to be its own script and not the leftover.
func TestStageClearsALeftoverFromAnInterruptedScan(t *testing.T) {
	fs := &countingFs{Fs: afero.NewMemMapFs()}
	script := "ConvertTo-Json @{ a = 1 }\n"
	path := powershell.StagedWindowsPath("iis", script)
	require.NoError(t, afero.WriteFile(fs, path, []byte("leftover"), 0o600))

	conn := &fakeConn{
		connType: shared.Type_SSH, platform: windowsPlatform(),
		fs: fs, caps: shared.Capability_RunCommand | shared.Capability_File,
	}
	staged, err := powershell.Stage(conn, "iis", script)
	require.NoError(t, err)
	assert.Equal(t, 1, fs.removes, "the leftover has to be cleared exactly once")
	assert.Empty(t, conn.commands,
		"clearing a leftover must not cost the chunked write's round trips")

	body, err := afero.ReadFile(fs, staged.Path)
	require.NoError(t, err)
	assert.Equal(t, script, string(body))
}

// The chunked path has no filesystem to remove through, so its cleanup is still
// a command - and it is the command most likely to break unnoticed, since it
// runs after the answer has been produced and only logs at debug.
func TestChunkedStagingRemovesOverTheCommandPath(t *testing.T) {
	conn := &fakeConn{
		connType: shared.Type_Winrm, platform: windowsPlatform(),
		fs:   readOnlyFs{afero.NewMemMapFs()},
		caps: shared.Capability_RunCommand | shared.Capability_File,
	}
	staged, err := powershell.Stage(conn, "iis",
		"ConvertTo-Json @{ a = 1 }\n"+strings.Repeat("#x\n", 50))
	require.NoError(t, err)
	written := len(conn.commands)

	staged.Remove()
	require.Len(t, conn.commands, written+1, "the chunked path still has to remove by command")
	assert.Contains(t, conn.commands[written], "Remove-Item")
	assert.Contains(t, conn.commands[written], staged.Path)
	assertStagingCommandShape(t, conn.commands)
}

// A filesystem that took the write and then refuses the delete must not leave
// the script on the target: the command path is still there to fall back on.
func TestFilesystemRemovalFallsBackToTheCommand(t *testing.T) {
	conn := &fakeConn{
		connType: shared.Type_SSH, platform: windowsPlatform(),
		fs:   undeletableFs{afero.NewMemMapFs()},
		caps: shared.Capability_RunCommand | shared.Capability_File,
	}
	staged, err := powershell.Stage(conn, "iis", "ConvertTo-Json @{ a = 1 }\n")
	require.NoError(t, err)
	require.Empty(t, conn.commands, "the write itself goes over the filesystem")

	staged.Remove()
	require.Len(t, conn.commands, 1, "a refused unlink has to fall back to the command")
	assert.Contains(t, conn.commands[0], "Remove-Item")
	assert.Contains(t, conn.commands[0], staged.Path)
	assertStagingCommandShape(t, conn.commands)
}

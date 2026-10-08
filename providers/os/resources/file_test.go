// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	sshcat "go.mondoo.com/mql/providers/os/connection/ssh/cat"
	"go.mondoo.com/mql/utils/syncx"
)

type fileCommandWrapper struct {
	commandRunner sshcat.CommandRunner
	sudo          *inventory.Sudo
	commands      []string
}

func (cw *fileCommandWrapper) RunCommand(command string) (*shared.Command, error) {
	cmd := shared.BuildSudoCommand(cw.sudo, command)
	cw.commands = append(cw.commands, cmd)
	return cw.commandRunner.RunCommand(cmd)
}

type sudoCatConnection struct {
	asset  *inventory.Asset
	runner *fileCommandWrapper
	fs     afero.Fs
}

func newSudoCatConnection(t *testing.T) *sudoCatConnection {
	t.Helper()

	fixturePath, err := filepath.Abs("../connection/ssh/cat/testdata/cat.toml")
	require.NoError(t, err)

	asset := &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "ubuntu",
			Version: "22.04",
			Family:  []string{"ubuntu", "linux"},
		},
	}
	mockConn, err := mock.New(0, asset, mock.WithPath(fixturePath))
	require.NoError(t, err)

	flags := map[string]*llx.Primitive{
		"sudo": llx.BoolPrimitive(true),
	}
	runner := &fileCommandWrapper{
		commandRunner: mockConn,
		sudo:          shared.ParseSudo(flags),
	}

	return &sudoCatConnection{
		asset:  asset,
		runner: runner,
		fs:     sshcat.New(runner),
	}
}

func (c *sudoCatConnection) ID() uint32                         { return 0 }
func (c *sudoCatConnection) ParentID() uint32                   { return 0 }
func (c *sudoCatConnection) Name() string                       { return "sudo-cat-test" }
func (c *sudoCatConnection) Type() shared.ConnectionType        { return shared.Type_SSH }
func (c *sudoCatConnection) Asset() *inventory.Asset            { return c.asset }
func (c *sudoCatConnection) UpdateAsset(asset *inventory.Asset) { c.asset = asset }
func (c *sudoCatConnection) Capabilities() shared.Capabilities {
	return shared.Capability_File | shared.Capability_RunCommand
}
func (c *sudoCatConnection) RunCommand(command string) (*shared.Command, error) {
	return c.runner.RunCommand(command)
}
func (c *sudoCatConnection) FileSystem() afero.Fs { return c.fs }
func (c *sudoCatConnection) FileInfo(path string) (shared.FileInfoDetails, error) {
	stat, err := (&afero.Afero{Fs: c.fs}).Stat(path)
	if err != nil {
		return shared.FileInfoDetails{}, err
	}
	sysStat, ok := stat.Sys().(*shared.FileInfo)
	if !ok {
		return shared.FileInfoDetails{}, errors.New("unexpected stat type")
	}

	return shared.FileInfoDetails{
		Mode: shared.FileModeDetails{FileMode: stat.Mode()},
		Size: stat.Size(),
		Uid:  sysStat.Uid,
		Gid:  sysStat.Gid,
	}, nil
}

func TestFileExistsSharesStatMetadataLoad(t *testing.T) {
	conn := newSudoCatConnection(t)
	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}

	raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData("/etc/ssh/sshd_config"),
	})
	require.NoError(t, err)

	file := raw.(*mqlFile)
	exists := file.GetExists()
	require.NoError(t, exists.Error)
	require.True(t, exists.Data)

	permissions := file.GetPermissions()
	require.NoError(t, permissions.Error)

	size := file.GetSize()
	require.NoError(t, size.Error)

	assert.Equal(t, 1, countRecordedCommands(conn.runner.commands, "sudo uname -s"))
	assert.Equal(t, 1, countRecordedCommands(conn.runner.commands, `sudo sh -c 'SL=0; test -L "$1" && SL=1; test -e "$1" -o $SL -eq 1 || exit 1; r=$(stat -L "$1" -c "$SL.%s.%f.%u.%g.%X.%Y.%C" 2>/dev/null) && printf "%s\n" "$r" || { [ -n "$r" ] && printf "%s\n" "$r" || stat "$1" -c "$SL.%s.%f.%u.%g.%X.%Y.%C" 2>/dev/null; }' _ /etc/ssh/sshd_config`))
}

func countRecordedCommands(commands []string, target string) int {
	count := 0
	for _, command := range commands {
		if command == target {
			count++
		}
	}
	return count
}

// A file that exists but is owned by a uid/gid with no passwd/group entry
// (common on minimal containers, or files left by a deleted user) must resolve
// file.user / file.group to null and fail cleanly, rather than erroring the
// whole check with "cannot find user for uid N".
func TestFileOwnership_UnknownUidGid(t *testing.T) {
	fixturePath, err := filepath.Abs("testdata/file_orphan_owner.toml")
	require.NoError(t, err)

	asset := &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "centos",
			Family: []string{"linux", "unix"},
		},
	}
	conn, err := mock.New(0, asset, mock.WithPath(fixturePath))
	require.NoError(t, err)

	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}

	raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData("/orphan"),
	})
	require.NoError(t, err)

	file := raw.(*mqlFile)
	// Simulate an existing file owned by a uid/gid that is not in passwd/group.
	file.Exists = plugin.TValue[bool]{Data: true, State: plugin.StateIsSet}
	file.statInfo = &shared.FileInfoDetails{
		Mode: shared.FileModeDetails{FileMode: os.FileMode(0o644)},
		Size: 10,
		Uid:  4242,
		Gid:  4242,
	}

	user := file.GetUser()
	require.NoError(t, user.Error, "file.user must not error for an unknown uid")
	assert.True(t, user.State&plugin.StateIsNull != 0, "file.user should be null for an unknown uid")

	group := file.GetGroup()
	require.NoError(t, group.Error, "file.group must not error for an unknown gid")
	assert.True(t, group.State&plugin.StateIsNull != 0, "file.group should be null for an unknown gid")
}

// Paths from a container's settings are read only as small regular files, so
// a device, FIFO or huge file cannot hang the scan or exhaust its memory.
func TestReadSmallRegularFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "profile.json"), []byte(`{"defaultAction":"SCMP_ACT_ALLOW"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "big.json"), make([]byte, 2048), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "dir"), 0o755))
	require.NoError(t, os.Symlink("profile.json", filepath.Join(dir, "link.json")))
	// mkfifo is missing on Windows, where the FIFO cases are skipped
	fifo := exec.Command("mkfifo", filepath.Join(dir, "fifo")).Run() == nil
	if fifo {
		require.NoError(t, os.Symlink("fifo", filepath.Join(dir, "fifolink")))
	}
	rt := memFSRuntime(t, afero.NewBasePathFs(afero.NewOsFs(), dir))

	content, ok := readSmallRegularFile(rt, "/profile.json", 1024)
	assert.True(t, ok)
	assert.Equal(t, `{"defaultAction":"SCMP_ACT_ALLOW"}`, content)
	content, ok = readSmallRegularFile(rt, "/link.json", 1024)
	assert.True(t, ok, "a link to a regular file is followed")
	assert.Equal(t, `{"defaultAction":"SCMP_ACT_ALLOW"}`, content)

	_, ok = readSmallRegularFile(rt, "/big.json", 1024)
	assert.False(t, ok, "over the size cap")
	_, ok = readSmallRegularFile(rt, "/big.json", 2048)
	assert.True(t, ok, "at the size cap")
	_, ok = readSmallRegularFile(rt, "/dir", 1024)
	assert.False(t, ok, "a directory")
	_, ok = readSmallRegularFile(rt, "profile.json", 1024)
	assert.False(t, ok, "a relative path")
	_, ok = readSmallRegularFile(rt, "/missing.json", 1024)
	assert.False(t, ok)
	if fifo {
		// reading a FIFO without a writer blocks forever
		_, ok = readSmallRegularFile(rt, "/fifo", 1024)
		assert.False(t, ok, "a FIFO")
		_, ok = readSmallRegularFile(rt, "/fifolink", 1024)
		assert.False(t, ok, "a link to a FIFO")
	}
}

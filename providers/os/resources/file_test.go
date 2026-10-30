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

func TestClassifyFsError(t *testing.T) {
	denied := &os.PathError{Op: "open", Path: `C:\secret.txt`, Err: os.ErrPermission}
	assert.ErrorIs(t, classifyFsError(denied), llx.ErrForbidden)
	assert.ErrorIs(t, classifyFsError(denied), os.ErrPermission)

	missing := &os.PathError{Op: "open", Path: `C:\missing.txt`, Err: os.ErrNotExist}
	assert.Same(t, missing, classifyFsError(missing))
	assert.NotErrorIs(t, classifyFsError(missing), llx.ErrForbidden)

	inUse := errors.New("The process cannot access the file because it is being used by another process.")
	assert.NotErrorIs(t, classifyFsError(inUse), llx.ErrForbidden)

	assert.NoError(t, classifyFsError(nil))
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

func TestIsAbsentPath(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o644))

	_, err := os.Stat(filepath.Join(file, ".ssh"))
	require.Error(t, err)
	assert.True(t, isAbsentPath(err), "a path below a regular file: %v", err)

	_, err = os.Stat(filepath.Join(t.TempDir(), "missing"))
	assert.True(t, isAbsentPath(err))

	assert.False(t, isAbsentPath(os.ErrPermission))
	assert.False(t, isAbsentPath(nil))
}

// A directory below a file (a user whose home is /dev/null) has no matches,
// like one that does not exist.
func TestGlobDirBelowAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "null")
	require.NoError(t, os.WriteFile(file, nil, 0o644))

	matches, err := globDir(afero.NewOsFs(), filepath.Join(file, ".config"), "*", false)
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestOctalMode(t *testing.T) {
	for mode, want := range map[int64]string{
		0:        "0000",
		0o7:      "0007",
		0o640:    "0640",
		0o4755:   "4755",
		0o1777:   "1777",
		0o7777:   "7777",
		0o100644: "0644", // file type bits are not permission bits
	} {
		assert.Equal(t, want, octalMode(mode), "%o", mode)
	}
}

// boundedReadFS can model a virtual file (size zero), a growing file, or a
// special target without ever opening a real FIFO and risking a stuck test.
type boundedReadFS struct {
	afero.Fs
	path      string
	mode      os.FileMode
	size      int64
	opens     int
	stats     int
	bytesRead int
}

type boundedReadInfo struct {
	os.FileInfo
	mode os.FileMode
	size int64
}

func (s boundedReadInfo) Mode() os.FileMode { return s.mode }
func (s boundedReadInfo) Size() int64       { return s.size }
func (s boundedReadInfo) IsDir() bool       { return s.mode.IsDir() }
func (fs *boundedReadFS) Stat(path string) (os.FileInfo, error) {
	fs.stats++
	info, err := fs.Fs.Stat(path)
	if err != nil || path != fs.path {
		return info, err
	}
	return boundedReadInfo{FileInfo: info, mode: fs.mode, size: fs.size}, nil
}
func (fs *boundedReadFS) Open(path string) (afero.File, error) {
	if path == fs.path {
		fs.opens++
	}
	file, err := fs.Fs.Open(path)
	if err != nil {
		return nil, err
	}
	return &boundedReadFile{File: file, fs: fs, path: path}, nil
}

type boundedReadFile struct {
	afero.File
	fs   *boundedReadFS
	path string
}

func (f *boundedReadFile) Stat() (os.FileInfo, error) { return f.fs.Stat(f.path) }
func (f *boundedReadFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	f.fs.bytesRead += n
	return n, err
}

func TestReadBoundedRegularFileRejectsSpecialBeforeOpen(t *testing.T) {
	for _, mode := range []os.FileMode{os.ModeNamedPipe, os.ModeDevice | os.ModeCharDevice, os.ModeSocket, os.ModeDir, os.ModeNamedPipe | os.ModeSymlink} {
		t.Run(mode.String(), func(t *testing.T) {
			mem := afero.NewMemMapFs()
			require.NoError(t, afero.WriteFile(mem, "/config", []byte("secret"), 0o644))
			fs := &boundedReadFS{Fs: mem, path: "/config", mode: mode}
			data, err := readBoundedRegularFile(&afero.Afero{Fs: fs}, "/config", 1024)
			require.ErrorContains(t, err, "regular file")
			assert.Nil(t, data)
			assert.Zero(t, fs.opens, "a FIFO must be rejected before an Open can block")
		})
	}
}

func TestReadBoundedRegularFileLimitsActualBytes(t *testing.T) {
	mem := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(mem, "/config", []byte("123456789"), 0o644))
	fs := &boundedReadFS{Fs: mem, path: "/config", mode: 0o644, size: 0}
	data, err := readBoundedRegularFile(&afero.Afero{Fs: fs}, "/config", 8)
	require.ErrorContains(t, err, "8 byte read limit")
	assert.Nil(t, data, "never return a truncated configuration as complete")
	assert.Equal(t, 9, fs.bytesRead, "read only the budget plus one overflow byte")
	fs.bytesRead = 0
	data, err = readBoundedRegularFile(&afero.Afero{Fs: fs}, "/config", 9)
	require.NoError(t, err)
	assert.Equal(t, "123456789", string(data), "zero-size virtual regular files remain readable")
	fs.mode = os.ModeSymlink | 0o644
	data, err = readBoundedRegularFile(&afero.Afero{Fs: fs}, "/config", 9)
	require.NoError(t, err)
	assert.Equal(t, "123456789", string(data), "command-backed target modes may retain the symlink bit")
}

func TestReadBoundedRegularFileRejectsOversizeBeforeOpen(t *testing.T) {
	mem := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(mem, "/config", []byte("x"), 0o644))
	fs := &boundedReadFS{Fs: mem, path: "/config", mode: 0o644, size: 4096}
	_, err := readBoundedRegularFile(&afero.Afero{Fs: fs}, "/config", 1024)
	require.ErrorContains(t, err, "1024 byte read limit")
	assert.Zero(t, fs.opens)
}

func TestFileContentRefusesSpecialOrOversize(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		size int64
	}{
		{"fifo", os.ModeNamedPipe, 0}, {"device", os.ModeDevice | os.ModeCharDevice, 0}, {"oversize", 0o644, maxFileContentSize + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem := afero.NewMemMapFs()
			require.NoError(t, afero.WriteFile(mem, "/config", []byte("x"), 0o644))
			fs := &boundedReadFS{Fs: mem, path: "/config", mode: tc.mode, size: tc.size}
			runtime := memFSRuntime(t, fs)
			raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{"path": llx.StringData("/config"), "exists": llx.BoolData(true)})
			require.NoError(t, err)
			result := raw.(*mqlFile).GetContent()
			require.Error(t, result.Error)
			assert.Empty(t, result.Data)
			assert.Zero(t, fs.opens)
		})
	}
}

func TestReadBoundedRegularFileRejectsNegativeLimitBeforeIO(t *testing.T) {
	fs := &boundedReadFS{Fs: afero.NewMemMapFs(), path: "/config"}
	data, err := readBoundedRegularFile(&afero.Afero{Fs: fs}, "/config", -1)
	require.ErrorContains(t, err, "invalid negative read limit -1")
	assert.Nil(t, data)
	assert.Zero(t, fs.stats, "an invalid internal budget must fail before inspecting a target")
	assert.Zero(t, fs.opens)
}

func TestWindowsBaseAndDir(t *testing.T) {
	tests := []struct {
		path, base, dir string
	}{
		{`C:\mqltest\plain.txt`, `plain.txt`, `C:\mqltest`},
		{`C:\mqltest\sub dir\a.log`, `a.log`, `C:\mqltest\sub dir`},
		{`C:/mqltest/plain.txt`, `plain.txt`, `C:/mqltest`},
		{`C:\mqltest/mixed.txt`, `mixed.txt`, `C:\mqltest`},
		{`C:\mqltest\`, `mqltest`, `C:\mqltest`},
		{`C:\a\b\..\c\file`, `file`, `C:\a\c`},
		{`C:\Windows`, `Windows`, `C:\`},
		{`C:/Windows`, `Windows`, `C:/`},
		{`C:\`, `\`, `C:\`},
		{`c:\x`, `x`, `c:\`},
		{`C:x`, `x`, `C:.`},
		{`\\server\share\dir\f.txt`, `f.txt`, `\\server\share\dir`},
		{`\\server\share\f.txt`, `f.txt`, `\\server\share\`},
		{`\\server\share`, `\`, `\\server\share`},
		{`\Windows\notepad.exe`, `notepad.exe`, `\Windows`},
		{`plain.txt`, `plain.txt`, `.`},
		{``, `.`, `.`},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.base, windowsBase(tc.path), "base of %q", tc.path)
		assert.Equal(t, tc.dir, windowsDir(tc.path), "dir of %q", tc.path)
	}
}

// basename and dirname split a Windows asset's path by Windows rules even when
// mql runs elsewhere, and keep splitting other assets on / only: a backslash
// is an ordinary character in a Linux file name.
func TestFileBasenameDirnameFollowAssetPlatform(t *testing.T) {
	for _, tc := range []struct {
		family    []string
		base, dir string
	}{
		{[]string{"windows", "os"}, `plain.txt`, `C:\mqltest`},
		{[]string{"linux", "unix", "os"}, `C:\mqltest\plain.txt`, `.`},
	} {
		conn := &sudoCatConnection{asset: &inventory.Asset{Platform: &inventory.Platform{Family: tc.family}}}
		f := &mqlFile{MqlRuntime: &plugin.Runtime{Connection: conn}}
		base, err := f.basename(`C:\mqltest\plain.txt`)
		require.NoError(t, err)
		dir, err := f.dirname(`C:\mqltest\plain.txt`)
		require.NoError(t, err)
		assert.Equal(t, tc.base, base, "%v", tc.family)
		assert.Equal(t, tc.dir, dir, "%v", tc.family)
	}
}

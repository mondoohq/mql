// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func TestParseLoggedInUsers(t *testing.T) {
	t.Run("windows sessions", func(t *testing.T) {
		out := " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n" +
			">mqladmin              rdp-tcp#0           2  Active          .  10/14/2026 9:12 AM\n" +
			" alice                                     3  Disc            5  10/14/2026 8:01 AM\n"
		users, err := parseLoggedInUsers(true, 0, out, "")
		require.NoError(t, err)
		assert.Equal(t, map[string]bool{"mqladmin": true, "alice": true}, users)
	})

	t.Run("windows nobody logged on", func(t *testing.T) {
		users, err := parseLoggedInUsers(true, 1, "", "No User exists for *\r\n")
		require.NoError(t, err)
		assert.Empty(t, users)
	})

	t.Run("windows nobody logged on, other display language", func(t *testing.T) {
		users, err := parseLoggedInUsers(true, 1, "", "Kein Benutzer für * vorhanden\r\n")
		require.NoError(t, err)
		assert.Empty(t, users)
	})

	t.Run("windows query.exe missing", func(t *testing.T) {
		_, err := parseLoggedInUsers(true, 9009, "",
			"'query' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n")
		assert.ErrorContains(t, err, "not recognized")
	})

	t.Run("windows error that mentions a wildcard", func(t *testing.T) {
		_, err := parseLoggedInUsers(true, 1, "", "Error 0x000006BA enumerating sessions for C:/Users/*\r\n")
		assert.Error(t, err)
		_, err = parseLoggedInUsers(true, 1, "", "Error [5]: Access is denied.\r\nQuery for * failed\r\n")
		assert.Error(t, err)
	})

	t.Run("windows query fails", func(t *testing.T) {
		_, err := parseLoggedInUsers(true, 1, "", "Invalid parameter(s)\r\nQUERY { PROCESS | SESSION | TERMSERVER | USER }\r\n")
		assert.Error(t, err)
	})

	t.Run("who", func(t *testing.T) {
		users, err := parseLoggedInUsers(false, 0, "root     pts/0        2026-10-14 09:12 (10.0.0.1)\nalice    tty1         2026-10-14 08:01\n", "")
		require.NoError(t, err)
		assert.Equal(t, map[string]bool{"root": true, "alice": true}, users)
	})
}

// Windows users and groups have no numeric IDs and all report -1. A user's
// primary group must then be null, not whichever group has -1 and was listed
// first, and no user or group may be found under -1.
func TestUserGroup_WindowsHasNoPrimaryGroup(t *testing.T) {
	fixturePath, err := filepath.Abs("testdata/group_dangling_member.toml")
	require.NoError(t, err)
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "centos", Family: []string{"linux", "unix"}},
	}, mock.WithPath(fixturePath))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	raw, err := CreateResource(runtime, "groups", nil)
	require.NoError(t, err)
	groups := raw.(*mqlGroups)
	require.NoError(t, groups.GetList().Error)

	raw, err = CreateResource(runtime, "users", nil)
	require.NoError(t, err)
	users := raw.(*mqlUsers)
	require.NoError(t, users.GetList().Error)

	var winGroups []any
	for _, g := range [][2]string{{"Access Control Assistance Operators", "S-1-5-32-579"}, {"Administrators", "S-1-5-32-544"}} {
		raw, err := CreateResource(runtime, "group", map[string]*llx.RawData{
			"name": llx.StringData(g[0]),
			"sid":  llx.StringData(g[1]),
			"gid":  llx.IntData(-1),
		})
		require.NoError(t, err)
		winGroups = append(winGroups, raw)
	}
	require.NoError(t, groups.refreshCache(winGroups))

	raw, err = CreateResource(runtime, "user", map[string]*llx.RawData{
		"name":    llx.StringData("mqladmin"),
		"sid":     llx.StringData("S-1-5-21-1-2-3-500"),
		"uid":     llx.IntData(-1),
		"gid":     llx.IntData(-1),
		"home":    llx.StringData(`C:\Users\mqladmin`),
		"shell":   llx.StringData(""),
		"enabled": llx.BoolData(true),
	})
	require.NoError(t, err)
	admin := raw.(*mqlUser)
	require.NoError(t, users.refreshCache([]any{admin}))

	group := admin.GetGroup()
	require.NoError(t, group.Error)
	assert.True(t, group.IsNull(), "a Windows user has no primary group, got %v", group.Data)

	_, err = groups.findID(-1)
	var notFound resources.NotFoundError
	assert.True(t, errors.As(err, &notFound), "no group has gid -1, got %v", err)
	_, err = users.findID(-1)
	assert.True(t, errors.As(err, &notFound), "no user has uid -1, got %v", err)
}

// sshd and guest on Alpine have /dev/null as their home. Looking for keys
// below it fails with ENOTDIR, which is no keys, not an error.
func TestUserKeysWithAHomeThatIsAFile(t *testing.T) {
	home := filepath.Join(t.TempDir(), "null")
	require.NoError(t, os.WriteFile(home, nil, 0o644))

	conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{Platform: &inventory.Platform{Name: "alpine", Family: []string{"linux", "unix"}}})
	rt := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
	u := &mqlUser{MqlRuntime: rt}
	u.Home = plugin.TValue[string]{Data: home, State: plugin.StateIsSet}

	keys, err := u.sshkeys()
	require.NoError(t, err)
	assert.Empty(t, keys)

	ak, err := u.authorizedkeys(home)
	require.NoError(t, err)
	list := ak.GetList()
	require.NoError(t, list.Error)
	assert.Empty(t, list.Data)
}

// typedFs reports a file type for selected paths, the way the local
// filesystem reports a FIFO, a socket or a symlink in ~/.ssh. MemMapFs can
// only hold regular files and directories.
type typedFs struct {
	afero.Fs
	lstat map[string]os.FileMode // type bits Lstat reports
	stat  map[string]os.FileMode // type bits Stat reports (symlink target)
	size  map[string]int64
}

type typedInfo struct {
	os.FileInfo
	mode os.FileMode
	size int64
}

func (i typedInfo) Mode() os.FileMode { return i.mode }
func (i typedInfo) Size() int64       { return i.size }
func (i typedInfo) IsDir() bool       { return i.mode.IsDir() }

func (f *typedFs) wrap(name string, fi os.FileInfo, modes map[string]os.FileMode) os.FileInfo {
	mode := fi.Mode()
	if m, ok := modes[name]; ok {
		mode = m | 0o600
	}
	size := fi.Size()
	if s, ok := f.size[name]; ok {
		size = s
	}
	return typedInfo{FileInfo: fi, mode: mode, size: size}
}

func (f *typedFs) Stat(name string) (os.FileInfo, error) {
	fi, err := f.Fs.Stat(name)
	if err != nil {
		return nil, err
	}
	return f.wrap(name, fi, f.stat), nil
}

func (f *typedFs) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	fi, err := f.Fs.Stat(name)
	if err != nil {
		return nil, true, err
	}
	return f.wrap(name, fi, f.lstat), true, nil
}

func TestSSHKeyCandidatesOnlyRegularFiles(t *testing.T) {
	dir := "/home/alice/.ssh"
	mem := afero.NewMemMapFs()
	for _, name := range []string{
		"id_ed25519", "fifo", "cm-socket", "link_to_key", "link_to_fifo", "dev", "huge",
	} {
		require.NoError(t, afero.WriteFile(mem, dir+"/"+name, []byte("x"), 0o600))
	}
	fs := &typedFs{
		Fs: mem,
		lstat: map[string]os.FileMode{
			dir + "/fifo":         os.ModeNamedPipe,
			dir + "/cm-socket":    os.ModeSocket,
			dir + "/link_to_key":  os.ModeSymlink,
			dir + "/link_to_fifo": os.ModeSymlink,
			dir + "/dev":          os.ModeDevice | os.ModeCharDevice,
		},
		stat: map[string]os.FileMode{
			dir + "/fifo":         os.ModeNamedPipe,
			dir + "/cm-socket":    os.ModeSocket,
			dir + "/link_to_fifo": os.ModeNamedPipe,
			dir + "/dev":          os.ModeDevice | os.ModeCharDevice,
		},
		size: map[string]int64{dir + "/huge": maxSSHKeyFileSize + 1},
	}

	got, err := sshKeyCandidates(fs, dir)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{dir + "/id_ed25519", dir + "/link_to_key"}, got)
}

// Over SSH --sudo the cat filesystem stats with `stat -L` and marks a symlink
// by adding ModeSymlink to the target's type, so a symlink to a regular file
// arrives as ModeSymlink alone and one to a FIFO as ModeSymlink|ModeNamedPipe.
func TestSSHKeyCandidatesCatFsSymlinks(t *testing.T) {
	dir := "/home/alice/.ssh"
	mem := afero.NewMemMapFs()
	for _, name := range []string{"link_to_key", "link_to_fifo"} {
		require.NoError(t, afero.WriteFile(mem, dir+"/"+name, []byte("x"), 0o600))
	}
	modes := map[string]os.FileMode{
		dir + "/link_to_key":  os.ModeSymlink,
		dir + "/link_to_fifo": os.ModeSymlink | os.ModeNamedPipe,
	}
	fs := &typedFs{Fs: mem, lstat: modes, stat: modes}

	got, err := sshKeyCandidates(fs, dir)
	require.NoError(t, err)
	assert.Equal(t, []string{dir + "/link_to_key"}, got)
}

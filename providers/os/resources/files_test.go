// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"go.mondoo.com/mql/providers/os/fsutil"
	"regexp"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
)

func TestFindNameMatcherIsABasenameGlob(t *testing.T) {
	m, err := findNameMatcher("*.conf")
	require.NoError(t, err, "a glob is not a regular expression")
	assert.True(t, m("/etc/c3-links/crlf.conf"))
	assert.True(t, m("/etc/c3-links/space name.conf"))
	assert.False(t, m("/etc/c3-links/crlf.conf.bak"))
	assert.False(t, m("/etc/c3-links.conf/x"), "only the last component is matched")

	m, err = findNameMatcher("in.conf")
	require.NoError(t, err)
	assert.True(t, m("/etc/c3-links/realdir/in.conf"))
	assert.False(t, m("/etc/c3-links/realdir/main.conf"), "a name is not a substring match")
	assert.False(t, m("/etc/in.confx"))

	m, err = findNameMatcher("su")
	require.NoError(t, err)
	assert.False(t, m("/usr/bin/sudo"))

	m, err = findNameMatcher("[!.]*")
	require.NoError(t, err)
	assert.True(t, m("/etc/x"))
	assert.False(t, m("/etc/.hidden"), "fnmatch's [! negation")

	m, err = findNameMatcher("")
	require.NoError(t, err)
	assert.Nil(t, m, "no name is no filter")

	_, err = findNameMatcher("[")
	assert.Error(t, err)
}

// noFindConnection is a host that runs commands but has no find, like the
// Amazon Linux 2023 and UBI micro images: its shell answers exit 127.
type noFindConnection struct {
	*fs.FileSystemConnection
}

func (noFindConnection) Capabilities() shared.Capabilities {
	return shared.Capability_File | shared.Capability_RunCommand
}

func (noFindConnection) RunCommand(command string) (*shared.Command, error) {
	return &shared.Command{
		Command:    command,
		Stdout:     &bytes.Buffer{},
		Stderr:     bytes.NewBufferString("sh: line 1: find: command not found\n"),
		ExitStatus: 127,
	}, nil
}

func TestFilesFindWithoutFindWalksTheFileSystem(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	writeMemFSFile(t, mockFS, "/etc/passwd", []byte("root:x:0:0::/root:/bin/sh\n"))
	writeMemFSFile(t, mockFS, "/etc/ssh/sshd_config", []byte("PermitRootLogin no\n"))
	require.NoError(t, mockFS.Chmod("/etc/ssh/sshd_config", 0o600))
	conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, &inventory.Asset{
		Platform: &inventory.Platform{Name: "amazonlinux", Family: []string{"redhat", "linux", "unix", "os"}},
	}, "", nil, mockFS)
	require.NoError(t, err)
	runtime := &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: noFindConnection{conn},
		Callback:   &providerCallbacks{},
	}

	find := func(args map[string]*llx.RawData) []string {
		t.Helper()
		res, err := CreateResource(runtime, "files.find", args)
		require.NoError(t, err)
		list := res.(*mqlFilesFind).GetList()
		require.NoError(t, list.Error)
		paths := []string{}
		for _, f := range list.Data {
			paths = append(paths, f.(*mqlFile).Path.Data)
		}
		return paths
	}

	assert.ElementsMatch(t, []string{"/etc/passwd", "/etc/ssh/sshd_config"},
		find(map[string]*llx.RawData{"from": llx.StringData("/etc"), "type": llx.StringData("file")}))
	assert.ElementsMatch(t, []string{"/etc/ssh/sshd_config"},
		find(map[string]*llx.RawData{"from": llx.StringData("/etc"), "name": llx.StringData("sshd_*")}))
	assert.ElementsMatch(t, []string{"/etc/passwd"},
		find(map[string]*llx.RawData{"from": llx.StringData("/etc"), "type": llx.StringData("file"), "permissions": llx.IntData(0o644)}))
}

type optionFindFS struct {
	afero.Fs
	cross []bool
}

func (f *optionFindFS) FindWithOptions(from string, r *regexp.Regexp, typ string, perm *uint32, depth *int, options fsutil.FindOptions) ([]string, error) {
	f.cross = append(f.cross, options.CrossFileSystems)
	return []string{"/etc/example.conf"}, nil
}
func TestFilesFindForwardsMountScope(t *testing.T) {
	for _, cross := range []bool{false, true} {
		f := &optionFindFS{Fs: afero.NewMemMapFs()}
		rt := memFSRuntime(t, f)
		res, err := CreateResource(rt, "files.find", map[string]*llx.RawData{"from": llx.StringData("/etc"), "xdev": llx.BoolData(cross)})
		require.NoError(t, err)
		found, err := res.(*mqlFilesFind).fsFilesFind(rt.Connection.(shared.Connection))
		require.NoError(t, err)
		require.Equal(t, []string{"/etc/example.conf"}, found)
		require.Equal(t, []bool{cross}, f.cross)
	}
}

// files.find(depth: 0) searches from alone; sharing an ID with the search of
// no depth would answer one with the other's cached list.
func TestFilesFindIDKeepsDepthZero(t *testing.T) {
	unbounded := &mqlFilesFind{From: plugin.TValue[string]{Data: `C:\mqltest`, State: plugin.StateIsSet}}
	depth0 := &mqlFilesFind{
		From:  plugin.TValue[string]{Data: `C:\mqltest`, State: plugin.StateIsSet},
		Depth: plugin.TValue[int64]{Data: 0, State: plugin.StateIsSet},
	}
	depth1 := &mqlFilesFind{
		From:  plugin.TValue[string]{Data: `C:\mqltest`, State: plugin.StateIsSet},
		Depth: plugin.TValue[int64]{Data: 1, State: plugin.StateIsSet},
	}

	ids := map[string]bool{}
	for _, f := range []*mqlFilesFind{unbounded, depth0, depth1} {
		id, err := f.id()
		require.NoError(t, err)
		ids[id] = true
	}
	assert.Len(t, ids, 3)
}

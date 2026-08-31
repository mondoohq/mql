// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/utils/syncx"
)

type procSocketCountingFs struct {
	afero.Fs
	links       map[string]string
	fdDirOpens  int
	readlinkOps int
}

func (fs *procSocketCountingFs) Open(path string) (afero.File, error) {
	if strings.HasPrefix(path, "/proc/") && strings.HasSuffix(path, "/fd") {
		fs.fdDirOpens++
	}
	return fs.Fs.Open(path)
}

func (fs *procSocketCountingFs) ReadlinkIfPossible(path string) (string, error) {
	fs.readlinkOps++
	link, ok := fs.links[path]
	if !ok {
		return "", os.ErrNotExist
	}
	return link, nil
}

type procResourceConn struct {
	asset *inventory.Asset
	fs    afero.Fs
}

func (c *procResourceConn) ID() uint32                                 { return 0 }
func (c *procResourceConn) ParentID() uint32                           { return 0 }
func (c *procResourceConn) RunCommand(string) (*shared.Command, error) { return nil, nil }
func (c *procResourceConn) FileInfo(string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, nil
}
func (c *procResourceConn) FileSystem() afero.Fs              { return c.fs }
func (c *procResourceConn) Name() string                      { return "proc-resource-test" }
func (c *procResourceConn) Type() shared.ConnectionType       { return "proc-resource-test" }
func (c *procResourceConn) Asset() *inventory.Asset           { return c.asset }
func (c *procResourceConn) UpdateAsset(*inventory.Asset)      {}
func (c *procResourceConn) Capabilities() shared.Capabilities { return shared.Capability_File }

func linuxAsset() *inventory.Asset {
	return &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "linux",
			Family: []string{"linux", "unix"},
		},
	}
}

func newResourcesRuntime(conn shared.Connection) *plugin.Runtime {
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

func writeProcProcess(t *testing.T, fs afero.Fs, pid, name string) {
	t.Helper()
	require.NoError(t, fs.MkdirAll("/proc/"+pid, 0o755))
	require.NoError(t, afero.WriteFile(fs, "/proc/"+pid+"/cmdline", []byte(name+"\x00"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/proc/"+pid+"/status", []byte("Name:\t"+name+"\nState:\tS (sleeping)\nPid:\t"+pid+"\n"), 0o644))
}

func writeProcSocketFds(t *testing.T, fs afero.Fs, links map[string]string, pid string, inodes ...int64) {
	t.Helper()
	fdDir := filepath.Join("/proc", pid, "fd")
	require.NoError(t, fs.MkdirAll(fdDir, 0o755))
	for i := range inodes {
		fdPath := filepath.Join(fdDir, strconv.Itoa(i+3))
		require.NoError(t, afero.WriteFile(fs, fdPath, []byte{}, 0o644))
		links[fdPath] = "socket:[" + strconv.FormatInt(inodes[i], 10) + "]"
	}
}

func TestMqlProcessesListDefersSocketEnumeration(t *testing.T) {
	baseFs := afero.NewMemMapFs()
	require.NoError(t, baseFs.MkdirAll("/proc", 0o755))
	writeProcProcess(t, baseFs, "1", "init")
	writeProcProcess(t, baseFs, "42", "bash")

	links := map[string]string{}
	writeProcSocketFds(t, baseFs, links, "1", 1001)
	writeProcSocketFds(t, baseFs, links, "42", 4201, 4202)

	fs := &procSocketCountingFs{Fs: baseFs, links: links}
	runtime := newResourcesRuntime(&procResourceConn{asset: linuxAsset(), fs: fs})

	obj, err := CreateResource(runtime, "processes", nil)
	require.NoError(t, err)
	procs := obj.(*mqlProcesses)

	res := procs.GetList()
	require.NoError(t, res.Error)
	require.Len(t, res.Data, 2)
	assert.Zero(t, fs.fdDirOpens, "processes.list should not walk /proc/<pid>/fd")
	assert.Zero(t, fs.readlinkOps, "processes.list should not resolve socket symlinks")
}

func TestMqlPortsProcessesBySocketEnumeratesOnDemand(t *testing.T) {
	baseFs := afero.NewMemMapFs()
	require.NoError(t, baseFs.MkdirAll("/proc", 0o755))
	writeProcProcess(t, baseFs, "1", "init")
	writeProcProcess(t, baseFs, "42", "bash")

	links := map[string]string{}
	writeProcSocketFds(t, baseFs, links, "1", 1001)
	writeProcSocketFds(t, baseFs, links, "42", 4201, 4202)

	fs := &procSocketCountingFs{Fs: baseFs, links: links}
	runtime := newResourcesRuntime(&procResourceConn{asset: linuxAsset(), fs: fs})

	processesObj, err := CreateResource(runtime, "processes", nil)
	require.NoError(t, err)
	processesRes := processesObj.(*mqlProcesses)
	list := processesRes.GetList()
	require.NoError(t, list.Error)
	assert.Zero(t, fs.fdDirOpens)
	assert.Zero(t, fs.readlinkOps)

	portsRes := &mqlPorts{MqlRuntime: runtime}
	mapping, err := portsRes.processesBySocket()
	require.NoError(t, err)
	assert.Greater(t, fs.fdDirOpens, 0, "socket ownership lookup should trigger /fd enumeration")
	assert.Greater(t, fs.readlinkOps, 0, "socket ownership lookup should resolve socket symlinks")

	proc := mapping[4202]
	require.NotNil(t, proc)
	assert.Equal(t, int64(42), proc.Pid.Data)
	assert.Equal(t, "bash", proc.Command.Data)
}

func TestMqlProcessesCollectSocketInodesPreservesErrors(t *testing.T) {
	runtime := newResourcesRuntime(&procResourceConn{
		asset: linuxAsset(),
		fs:    afero.NewMemMapFs(),
	})
	procs := &mqlProcesses{MqlRuntime: runtime}
	all := []any{
		&mqlProcess{
			Pid: plugin.TValue[int64]{Data: 1, State: plugin.StateIsSet},
			mqlProcessInternal: mqlProcessInternal{
				SocketInodes: plugin.TValue[[]int64]{
					Data:  []int64{},
					State: plugin.StateIsSet,
				},
			},
		},
	}

	err := procs.collectSocketInodes(all)
	require.EqualError(t, err, "could not retrieve processes socket inodes")
}

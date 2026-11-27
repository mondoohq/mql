// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
)

func newMacosProcessRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "macos",
			Family: []string{"unix", "darwin"},
		},
	}, mock.WithPath("./processes/testdata/osx.toml"))
	require.NoError(t, err)

	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

// TestProcessWithoutPidDoesNotPanic covers mondoohq/mql#10355: querying the
// bare `process` resource creates it without a pid, so gatherProcessInfo looks
// up pid 0. macOS `ps` starts at pid 1, so that lookup misses and the process
// manager used to hand back (nil, nil), which the accessors dereferenced.
func TestProcessWithoutPidDoesNotPanic(t *testing.T) {
	proc := &mqlProcess{MqlRuntime: newMacosProcessRuntime(t)}

	state := proc.GetState()
	require.Error(t, state.Error, "a process that cannot be resolved must report an error")
	assert.Empty(t, state.Data)

	executable := proc.GetExecutable()
	require.Error(t, executable.Error)
	assert.Empty(t, executable.Data)

	command := proc.GetCommand()
	require.Error(t, command.Error)
	assert.Empty(t, command.Data)

	// Every field failed for the same reason, so they must say the same thing.
	// The memoized error used to surface only from the second accessor onwards,
	// which reported one cause as two unrelated-looking errors.
	assert.Equal(t, state.Error.Error(), executable.Error.Error())
	assert.Equal(t, state.Error.Error(), command.Error.Error())
	assert.Contains(t, state.Error.Error(), "process 0 does not exist")
}

// TestProcessWithKnownPidResolves proves the not-found path did not cost us the
// happy path: a pid that is present in `ps` still populates every field.
func TestProcessWithKnownPidResolves(t *testing.T) {
	proc := &mqlProcess{MqlRuntime: newMacosProcessRuntime(t)}
	proc.Pid = plugin.TValue[int64]{Data: 1, State: plugin.StateIsSet}

	executable := proc.GetExecutable()
	require.NoError(t, executable.Error)
	assert.Equal(t, "launchd", executable.Data)

	command := proc.GetCommand()
	require.NoError(t, command.Error)
	assert.Equal(t, "/sbin/launchd", command.Data)

	state := proc.GetState()
	require.NoError(t, state.Error)
}

// procCmdConn is a Linux connection that reads /proc with commands, as a
// running docker container is. It wraps a mock connection in a type of its own,
// since the mock type itself is routed to ps, and answers the two dump
// commands from fixtures, recording every command it runs.
type procCmdConn struct {
	*mock.Connection
	procDump string
	sockDump string
	commands []string
}

func (c *procCmdConn) Type() shared.ConnectionType { return shared.Type_DockerContainer }
func (c *procCmdConn) Capabilities() shared.Capabilities {
	return shared.Capability_File | shared.Capability_RunCommand
}
func (c *procCmdConn) Asset() *inventory.Asset {
	return &inventory.Asset{Platform: &inventory.Platform{Name: "debian", Family: []string{"debian", "linux", "unix", "os"}}}
}

func (c *procCmdConn) RunCommand(command string) (*shared.Command, error) {
	c.commands = append(c.commands, command)
	out, exit := "", 127
	switch {
	case strings.Contains(command, "base64"):
		out, exit = c.procDump, 0
	case strings.Contains(command, "ls -l"):
		out, exit = c.sockDump, 0
	}
	return &shared.Command{Command: command, Stdout: bytes.NewBufferString(out), Stderr: &bytes.Buffer{}, ExitStatus: exit}, nil
}

// Listing processes reads no socket: the Kubernetes policy filters list
// processes on every Linux asset and only ports needs them. The fixtures are
// the dumps of a php:8.3-apache container (Debian 13.7), see
// processes/linuxproc_dump_test.go.
func TestProcessesListLeavesSocketsToPorts(t *testing.T) {
	base, err := mock.New(0, &inventory.Asset{})
	require.NoError(t, err)
	procDump, err := os.ReadFile("./processes/testdata/procdump-php83-apache-debian13.bin")
	require.NoError(t, err)
	sockDump, err := os.ReadFile("./processes/testdata/sockdump-php83-apache-debian13.txt")
	require.NoError(t, err)
	conn := &procCmdConn{Connection: base, procDump: string(procDump), sockDump: string(sockDump)}
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	obj, err := CreateResource(runtime, ResourceProcesses, nil)
	require.NoError(t, err)
	procs := obj.(*mqlProcesses)

	list := procs.GetList()
	require.NoError(t, list.Error)
	assert.Len(t, list.Data, 6)
	require.Len(t, conn.commands, 1, "one command lists the processes")
	assert.Contains(t, conn.commands[0], "base64")

	bySocket, err := procs.bySocket()
	require.NoError(t, err)
	require.Len(t, bySocket, 1)
	assert.Equal(t, int64(1), bySocket[1424795].Pid.Data)
	require.Len(t, conn.commands, 2, "sockets are read when ports asks")
	assert.Contains(t, conn.commands[1], "ls -l")

	_, err = procs.bySocket()
	require.NoError(t, err)
	assert.Len(t, conn.commands, 2, "and only once")
}

// Synthetic: a socket held by a process that started after the listing has
// no listed process to point at.
func TestIndexSockets(t *testing.T) {
	p1 := &mqlProcess{Pid: plugin.TValue[int64]{Data: 1, State: plugin.StateIsSet}}
	p2 := &mqlProcess{Pid: plugin.TValue[int64]{Data: 2, State: plugin.StateIsSet}}
	res := indexSockets([]any{p1, p2}, map[int64]plugin.TValue[[]int64]{
		1: {Data: []int64{10, 11}},
		2: {Data: []int64{}},
		3: {Data: []int64{30}},
	})
	assert.Equal(t, map[int64]*mqlProcess{10: p1, 11: p1}, res)
}

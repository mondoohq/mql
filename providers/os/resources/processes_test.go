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

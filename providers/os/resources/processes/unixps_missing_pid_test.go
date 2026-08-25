// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/processes"
)

func macosProcessManager(t *testing.T) processes.OSProcessManager {
	t.Helper()

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "macos",
			Family: []string{"unix", "darwin"},
		},
	}, mock.WithPath("./testdata/osx.toml"))
	require.NoError(t, err)

	pm, err := processes.ResolveManager(conn)
	require.NoError(t, err)
	return pm
}

// TestUnixProcessManagerMissingPidReturnsError pins the OSProcessManager
// contract that a pid which cannot be resolved is reported as an error, the
// way the linux, docker and windows managers already do. Returning (nil, nil)
// made every caller that only checked err a nil dereference waiting to happen
// (mondoohq/mql#10355).
func TestUnixProcessManagerMissingPidReturnsError(t *testing.T) {
	pm := macosProcessManager(t)

	// macOS `ps` starts at pid 1, so pid 0 never resolves. This is the pid a
	// bare `process` resource carries, since it is created without one.
	proc, err := pm.Process(0)
	require.Error(t, err)
	assert.Nil(t, proc)

	proc, err = pm.Process(9999999)
	require.Error(t, err)
	assert.Nil(t, proc)
}

// TestUnixProcessManagerExistsHandlesMissingPid guards the other half of the
// contract: Exists must keep reporting a missing pid as (false, nil) and not
// inherit the not-found error that Process now returns.
func TestUnixProcessManagerExistsHandlesMissingPid(t *testing.T) {
	pm := macosProcessManager(t)

	exists, err := pm.Exists(0)
	require.NoError(t, err)
	assert.False(t, exists)

	exists, err = pm.Exists(1)
	require.NoError(t, err)
	assert.True(t, exists)
}

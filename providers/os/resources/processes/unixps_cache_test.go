// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// countingConn wraps a real connection and counts how many times each command
// is executed, so we can prove the `ps` invocation is memoized.
type countingConn struct {
	shared.Connection
	mu    sync.Mutex
	calls map[string]int
}

func (c *countingConn) RunCommand(command string) (*shared.Command, error) {
	c.mu.Lock()
	if c.calls == nil {
		c.calls = map[string]int{}
	}
	c.calls[command]++
	c.mu.Unlock()
	return c.Connection.RunCommand(command)
}

// psCalls returns the total number of `ps ...` commands executed.
func (c *countingConn) psCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	for cmd, n := range c.calls {
		if strings.HasPrefix(cmd, "ps ") {
			total += n
		}
	}
	return total
}

// TestUnixProcessManagerCachesPsOutput proves that repeated Exists/Process/List
// calls on a UnixProcessManager run the underlying `ps` command only once.
// Before memoization, each Exists+Process pair alone ran two full `ps` commands,
// scaling to ~2N invocations for N process(pid:) lookups over SSH.
func TestUnixProcessManagerCachesPsOutput(t *testing.T) {
	base, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"unix", "freebsd"},
		},
	}, mock.WithPath("./testdata/freebsd12.toml"))
	require.NoError(t, err)

	conn := &countingConn{Connection: base}
	upm := &UnixProcessManager{conn: conn, platform: base.Asset().Platform}

	// A mix of List / Exists / Process calls that would each have re-run `ps`.
	list, err := upm.List()
	require.NoError(t, err)
	require.Equal(t, 41, len(list))

	exists, err := upm.Exists(0)
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = upm.Exists(9999999)
	require.NoError(t, err)
	assert.False(t, exists)

	proc, err := upm.Process(88)
	require.NoError(t, err)
	require.NotNil(t, proc)
	assert.Equal(t, "[Timer]", proc.Command)

	missing, err := upm.Process(9999999)
	require.Error(t, err, "an unresolvable pid must be reported as an error, not (nil, nil)")
	assert.Nil(t, missing)

	// Despite 6 lookups, `ps` must have run exactly once.
	assert.Equal(t, 1, conn.psCalls(), "expected the ps command to run exactly once")
}

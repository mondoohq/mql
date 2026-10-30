// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"io"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type mqlCommandInternal struct {
	lock             sync.Mutex
	commandIsRunning bool
}

func (c *mqlCommand) id() (string, error) {
	return c.Command.Data, c.Command.Error
}

func (c *mqlCommand) execute(cmd string) error {
	c.lock.Lock()
	if c.commandIsRunning {
		c.lock.Unlock()
		return plugin.NotReady
	}
	c.commandIsRunning = true
	c.lock.Unlock()

	x, err := c.MqlRuntime.Connection.(shared.Connection).RunCommand(cmd)
	if err != nil {
		c.Exitcode = plugin.TValue[int64]{Error: err, State: plugin.StateIsSet}
		c.Stdout = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		c.Stderr = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		return err
	}

	c.Exitcode = plugin.TValue[int64]{Data: int64(x.ExitStatus), State: plugin.StateIsSet}

	stdout, err := io.ReadAll(x.Stdout)
	c.Stdout = plugin.TValue[string]{Data: string(stdout), Error: err, State: plugin.StateIsSet}

	stderr, err := io.ReadAll(x.Stderr)
	c.Stderr = plugin.TValue[string]{Data: string(stderr), Error: err, State: plugin.StateIsSet}

	c.lock.Lock()
	c.commandIsRunning = false
	c.lock.Unlock()

	return nil
}

func (c *mqlCommand) stdout(cmd string) (string, error) {
	// note: we ignore the return value because everything is set in execute
	return "", c.execute(cmd)
}

func (c *mqlCommand) stderr(cmd string) (string, error) {
	// note: we ignore the return value because everything is set in execute
	return "", c.execute(cmd)
}

func (c *mqlCommand) exitcode(cmd string) (int64, error) {
	// note: we ignore the return value because everything is set in execute
	return 0, c.execute(cmd)
}

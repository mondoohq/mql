// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
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

// commandRun is the settled result of a `command` resource: the exit code and
// both output streams, read only once every underlying TValue is known to be
// error free.
type commandRun struct {
	exitcode int64
	stdout   string
	stderr   string
}

// commandResult reads an already-created `command` resource and reports an
// error whenever the command could not run at all.
//
// This check is not optional. A connection without command execution answers
// every field of the resource with an error and leaves Data at its zero value,
// so `exitcode` reads as 0 and stdout reads as "". Code that trusts Data
// without consulting Error therefore sees a command that succeeded and printed
// nothing, and goes on to report the parse of an empty string as a measured
// fact. On a container image scan that is how `macos.filevault.enabled` came
// back as a confident `false`.
//
// A non-zero exit code is deliberately not an error here: callers that branch
// on a specific code (lvm's 127 for "not installed", softwareupdate's exit 1
// for "no updates available") need to see it. Callers that only want stdout
// from a command that must succeed should use commandOutput instead.
func commandResult(cmd *mqlCommand) (commandRun, error) {
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return commandRun{}, exit.Error
	}
	stdout := cmd.GetStdout()
	if stdout.Error != nil {
		return commandRun{}, stdout.Error
	}
	return commandRun{
		exitcode: exit.Data,
		stdout:   stdout.Data,
		stderr:   cmd.GetStderr().Data,
	}, nil
}

// commandOutput returns the stdout of an already-created `command` resource,
// or an error if the command could not run or exited non-zero. `what` names
// the command in the error message.
func commandOutput(cmd *mqlCommand, what string) (string, error) {
	run, err := commandResult(cmd)
	if err != nil {
		return "", err
	}
	if run.exitcode != 0 {
		return "", errors.New(what + " failed: " + run.stderr)
	}
	return run.stdout, nil
}

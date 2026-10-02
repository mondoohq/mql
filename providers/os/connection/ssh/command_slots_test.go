// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

func TestWindowsMaxCommands(t *testing.T) {
	t.Setenv(windowsMaxCommandsEnv, "")
	assert.Equal(t, defaultWindowsMaxCommands, windowsMaxCommands(nil))
	assert.Equal(t, 2, windowsMaxCommands(map[string]string{windowsMaxCommandsOption: "2"}))
	assert.Equal(t, 0, windowsMaxCommands(map[string]string{windowsMaxCommandsOption: "0"}))
	assert.Equal(t, defaultWindowsMaxCommands, windowsMaxCommands(map[string]string{windowsMaxCommandsOption: "many"}))
	assert.Equal(t, defaultWindowsMaxCommands, windowsMaxCommands(map[string]string{windowsMaxCommandsOption: "-1"}))
	// a limit above the cap is capped, not taken as is
	assert.Equal(t, maxWindowsMaxCommands, windowsMaxCommands(map[string]string{windowsMaxCommandsOption: "99999999999"}))
	assert.Equal(t, maxWindowsMaxCommands, windowsMaxCommands(map[string]string{windowsMaxCommandsOption: "65"}))

	t.Setenv(windowsMaxCommandsEnv, "3")
	assert.Equal(t, 3, windowsMaxCommands(nil))
	// the connection's option wins over the environment
	assert.Equal(t, 1, windowsMaxCommands(map[string]string{windowsMaxCommandsOption: "1"}))
}

func TestStartsPowershell(t *testing.T) {
	assert.True(t, startsPowershell(powershell.Encode("Get-Date")))
	assert.True(t, startsPowershell(powershell.Wrap("Get-Date")))
	assert.True(t, startsPowershell(powershell.StagedCommand(`C:\x.ps1`)))
	assert.False(t, startsPowershell(powershell.EncodeUnix("Get-Date")))
	assert.False(t, startsPowershell("uname -s"))
	assert.False(t, startsPowershell("cat /etc/powershell.conf"))
}

// concurrencyRunner answers the shell probe like the given shell and records
// how many other commands ran at the same time.
type concurrencyRunner struct {
	shell   string
	running atomic.Int32
	max     atomic.Int32
}

func (r *concurrencyRunner) run(command string) (*shared.Command, error) {
	out := "ok"
	if command == shellProbe {
		out = r.shell
	} else {
		n := r.running.Add(1)
		for {
			m := r.max.Load()
			if n <= m || r.max.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		r.running.Add(-1)
	}
	return &shared.Command{Command: command, Stdout: bytes.NewBufferString(out), Stderr: &bytes.Buffer{}}, nil
}

func runConcurrently(t *testing.T, c *Connection, commands ...string) {
	// the first PowerShell command detects the shell, as in a scan, where
	// platform detection runs before the resources do
	_, err := c.RunCommand(commands[0])
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 12 {
		for _, cmd := range commands {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := c.RunCommand(cmd)
				// assert, not require: FailNow must not run outside the
				// test's goroutine
				assert.NoError(t, err)
			}()
		}
	}
	wg.Wait()
}

func TestCommandSlotsOnWindows(t *testing.T) {
	t.Setenv(windowsMaxCommandsEnv, "")
	for name, probe := range map[string]string{
		"powershell": "%OS%\r\nDesktop\r\n",
		"cmd.exe":    "Windows_NT;$PSVersionTable.PSEdition\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			r := &concurrencyRunner{shell: probe}
			c := &Connection{conf: &inventory.Config{Options: map[string]string{windowsMaxCommandsOption: "2"}}, rawRunner: r.run}
			runConcurrently(t, c, powershell.Encode("Get-Date"), "hostname")
			assert.Equal(t, int32(2), r.max.Load())
		})
	}

	t.Run("sudo", func(t *testing.T) {
		r := &concurrencyRunner{shell: "%OS%\r\nDesktop\r\n"}
		c := &Connection{
			conf:      &inventory.Config{Options: map[string]string{windowsMaxCommandsOption: "2"}},
			Sudo:      &inventory.Sudo{Active: true},
			rawRunner: r.run,
		}
		// sudo never probes the shell; another command found it
		c.shell = parseShellProbe(r.shell)
		c.shellDetected.Store(true)
		runConcurrently(t, c, powershell.Encode("Get-Date"))
		assert.Equal(t, int32(2), r.max.Load())
	})

	t.Run("no limit", func(t *testing.T) {
		r := &concurrencyRunner{shell: "%OS%\r\nDesktop\r\n"}
		c := &Connection{conf: &inventory.Config{Options: map[string]string{windowsMaxCommandsOption: "0"}}, rawRunner: r.run}
		runConcurrently(t, c, powershell.Encode("Get-Date"))
		assert.Greater(t, r.max.Load(), int32(2))
	})
}

func TestCommandSlotsNotOnUnix(t *testing.T) {
	r := &concurrencyRunner{shell: "%OS%\n"}
	c := &Connection{conf: &inventory.Config{Options: map[string]string{windowsMaxCommandsOption: "1"}}, rawRunner: r.run}
	runConcurrently(t, c, "uname -s", powershell.EncodeUnix("Get-Date"))
	assert.Greater(t, r.max.Load(), int32(1))
}

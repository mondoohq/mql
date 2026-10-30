// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

const (
	// defaultWindowsMaxCommands is how many commands run at once over one SSH
	// connection to Windows. Every command there starts a PowerShell process,
	// which takes a CPU for most of a second before it runs a line of the
	// script; a scan starts many at once and they starve each other.
	defaultWindowsMaxCommands = 4

	// maxWindowsMaxCommands caps a configured limit. More concurrent
	// PowerShell processes than this only starve each other on the target,
	// and the limit sizes the slot channel.
	maxWindowsMaxCommands = 64

	// windowsMaxCommandsEnv and windowsMaxCommandsOption set it: a number up
	// to maxWindowsMaxCommands, and 0 for no limit.
	windowsMaxCommandsEnv    = "MONDOO_SSH_WINDOWS_MAX_COMMANDS"
	windowsMaxCommandsOption = "ssh_windows_max_commands"
)

// windowsMaxCommands reads the limit from the connection's options, then the
// environment, and falls back to the default. options may be nil: a nil map
// reads as empty.
func windowsMaxCommands(options map[string]string) int {
	for _, v := range []string{options[windowsMaxCommandsOption], os.Getenv(windowsMaxCommandsEnv)} {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			log.Warn().Str("value", v).Msg("ssh> ignoring an invalid limit of concurrent Windows commands")
			continue
		}
		if n > maxWindowsMaxCommands {
			log.Warn().Int("value", n).Int("max", maxWindowsMaxCommands).Msg("ssh> capping the limit of concurrent Windows commands")
			return maxWindowsMaxCommands
		}
		return n
	}
	return defaultWindowsMaxCommands
}

// startsPowershell reports whether a command starts Windows PowerShell, as
// opposed to a plain command such as `uname -s` or pwsh, which Unix targets
// run too.
func startsPowershell(command string) bool {
	lower := strings.ToLower(strings.TrimSpace(command))
	return strings.HasPrefix(lower, "powershell ") || strings.HasPrefix(lower, "powershell.exe ")
}

func (c *Connection) acquireCommandSlotContext(ctx context.Context, command string) (func(), error) {
	var windows bool
	if startsPowershell(command) {
		shell, err := c.remoteShellContext(ctx)
		if err != nil {
			return nil, err
		}
		windows = shell.isWindows()
	} else {
		windows = c.shellDetected.Load() && c.shell.isWindows()
	}
	if !windows {
		return func() {}, nil
	}

	c.slotsOnce.Do(func() {
		var options map[string]string
		if c.conf != nil {
			options = c.conf.Options
		}
		if n := windowsMaxCommands(options); n > 0 {
			c.slots = make(chan struct{}, n)
			log.Debug().Int("max", n).Msg("ssh> limit concurrent commands on Windows")
		}
	})
	if c.slots == nil {
		return func() {}, nil
	}
	select {
	case c.slots <- struct{}{}:
		return func() { <-c.slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"bufio"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// parseShowProperties parses key=value output from systemctl show.
func parseShowProperties(input io.Reader) (map[string]string, error) {
	props := map[string]string{}
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if existing, ok := props[key]; ok {
			props[key] = existing + "\n" + value
		} else {
			props[key] = value
		}
	}
	return props, scanner.Err()
}

// buildShowPropertyCommand builds a "systemctl show --property=X unit" command
// with custom properties, escaping all arguments for shell safety.
func buildShowPropertyCommand(properties string, unit string) string {
	args := []string{"systemctl", "show", "--property=" + properties, unit}
	escaped := make([]string, len(args))
	for i := range args {
		escaped[i] = shared.ShellEscape(args[i])
	}
	return strings.Join(escaped, " ")
}

// applyUnitFileState sets enabled, masked, and static flags from a systemd
// unit file state string. This is the shared logic used by timer, socket,
// and service unit file parsing.
func applyUnitFileState(enabled, masked, static *bool, unitFileState string) {
	*enabled = unitFileState == "enabled" || unitFileState == "enabled-runtime"
	*masked = strings.HasPrefix(unitFileState, "masked")
	*static = unitFileState == "static"
}

// SystemdTimerLister can list and look up systemd timers.
type SystemdTimerLister interface {
	List() ([]*SystemdTimer, error)
	Get(name string) (*SystemdTimer, error)
	ShowTimerProperties(name string) (map[string]string, error)
}

// SystemdSocketLister can list and look up systemd sockets.
type SystemdSocketLister interface {
	List() ([]*SystemdSocket, error)
	Get(name string) (*SystemdSocket, error)
	ShowSocketProperties(name string) (map[string]string, error)
}

// ResolveSystemdTimerManager returns a command-based manager when the
// connection supports command execution, otherwise a filesystem-based manager.
func ResolveSystemdTimerManager(conn shared.Connection) SystemdTimerLister {
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return &SystemdFSTimerManager{Fs: conn.FileSystem()}
	}
	return NewSystemdTimerManager(conn)
}

// ResolveSystemdSocketManager returns a command-based manager when the
// connection supports command execution, otherwise a filesystem-based manager.
func ResolveSystemdSocketManager(conn shared.Connection) SystemdSocketLister {
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return &SystemdFSSocketManager{Fs: conn.FileSystem()}
	}
	return NewSystemdSocketManager(conn)
}

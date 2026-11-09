// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// enterHostNamespaces runs a command in every namespace of the host's init
// process. A container that shares the host's PID namespace sees that process
// as PID 1.
const enterHostNamespaces = "nsenter -t 1 -a --"

// BuildHostNamespacesCommand builds the command line that runs cmd in the
// namespaces of PID 1, as Bottlerocket's sheltie does from its admin
// container. The connection's elevation runs nsenter when it is active; its
// shell option does not apply, the shell is given here.
//
// A plain argv runs as is. A shell command line, or one that starts with
// VAR=value words, runs in shell, a path in the caller's mount namespace:
// the host may have no usable shell. An argv that starts a shell itself
// (`sh -c '...'`) runs in that shell too. The host reaches it through
// /proc/$$/root, the root directory of the login shell that runs the command
// line. $$ is expanded by that shell before nsenter starts, and the process
// stays alive until the command ends, as its parent or as the elevation it
// was replaced by.
func BuildHostNamespacesCommand(sudo *inventory.Sudo, shell string, cmd string) string {
	var sb strings.Builder
	if sudo != nil && sudo.Active {
		executable := sudo.Executable
		if executable == "" {
			executable = ElevationSudo
		}
		sb.WriteString(executable + " ")
		if len(sudo.User) > 0 {
			sb.WriteString("-u " + sudo.User + " ")
		}
	}
	sb.WriteString(enterHostNamespaces + " ")

	hostShell := "/proc/$$/root" + shell
	trimmed := strings.TrimLeft(cmd, " \t")
	if needsShellForSudo(cmd) || envAssignmentRegex.MatchString(trimmed) {
		sb.WriteString(hostShell + " -c " + ShellEscape(cmd))
		return sb.String()
	}
	first, rest, _ := strings.Cut(trimmed, " ")
	if posixShells[first] {
		sb.WriteString(hostShell)
		if rest != "" {
			sb.WriteString(" " + rest)
		}
		return sb.String()
	}
	sb.WriteString(cmd)
	return sb.String()
}

// posixShells are the programs that start a shell for a command line. On the
// host they may be missing or restricted.
var posixShells = map[string]bool{
	"sh": true, "/bin/sh": true, "/usr/bin/sh": true,
	"bash": true, "/bin/bash": true, "/usr/bin/bash": true,
}

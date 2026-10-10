// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"io"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// A Bottlerocket host has no SSH daemon and no usable shell. The way in is
// its admin host container, which runs sshd. The container shares the host's
// PID and network namespaces, but its mount namespace holds its own Amazon
// Linux file system, with the host's root file system at
// /.bottlerocket/rootfs and the host's os-release bind-mounted as
// /etc/bottlerocket-release. A scan of what the container sees therefore
// reports the container's files, packages and services under the host's
// platform name.
//
// `sudo sheltie` in the container is how Bottlerocket documents reaching the
// host: nsenter into every namespace of PID 1, the host's init, with the
// container's static bash as the shell. The connection does the same for
// every command and file read once it detects the container.
const (
	// bottlerocketProbe prints the host's os-release from inside a
	// Bottlerocket host container. It needs no privileges.
	bottlerocketProbe = "cat /.bottlerocket/rootfs/usr/lib/os-release"
	// mountNamespaceProbe prints the mount namespaces of the command itself
	// and of PID 1. Reading PID 1's needs root.
	mountNamespaceProbe = "readlink /proc/self/ns/mnt /proc/1/ns/mnt"
	// bottlerocketAdminShell is the admin container's static bash, which
	// sheltie runs on the host. It does not depend on the host's libraries.
	bottlerocketAdminShell = "/opt/bin/bash"
)

// bottlerocketHost is set on a connection that reaches a Bottlerocket host
// through its admin container.
type bottlerocketHost struct {
	// title is the host's PRETTY_NAME, for messages
	title string
	// enter is true when the connection itself has to enter the host's
	// namespaces. It is false when the configured elevation already runs
	// commands there, such as a wrapper around sheltie.
	enter bool
}

// BottlerocketAdminContainer reports whether the connection reaches a
// Bottlerocket host through its admin container.
func (c *Connection) BottlerocketAdminContainer() bool {
	return c.bottlerocket != nil
}

// entersHost reports whether commands and file reads are sent into the
// Bottlerocket host's namespaces by this connection.
func (c *Connection) entersHost() bool {
	return c.bottlerocket != nil && c.bottlerocket.enter
}

// detectBottlerocketAdminContainer finds out whether the connection landed in
// a Bottlerocket admin container. If so, it makes every later command and
// file read run in the host's namespaces, or fails when the connection has no
// root to do that: a scan of the container would report wrong results under
// the host's name.
//
// The signals, in order:
//  1. /.bottlerocket/rootfs/usr/lib/os-release says ID=bottlerocket: the
//     host's root file system is mounted where Bottlerocket mounts it into
//     its host containers. Any user can read it.
//  2. With the connection's elevation, /proc/self/ns/mnt differs from
//     /proc/1/ns/mnt: the command runs in a mount namespace other than the
//     host init's. Equal means the elevation already enters the host.
//  3. A command line run in the host's namespaces with the container's shell
//     lands in PID 1's mount namespace.
func (c *Connection) detectBottlerocketAdminContainer() error {
	out, err := c.runRaw(bottlerocketProbe)
	if err != nil || out == nil || out.ExitStatus != 0 {
		return nil
	}
	osRelease, _ := io.ReadAll(out.Stdout)
	osr := parseOsRelease(string(osRelease))
	if osr["ID"] != "bottlerocket" {
		return nil
	}
	title := osr["PRETTY_NAME"]
	if title == "" {
		title = "Bottlerocket"
	}
	log.Debug().Str("host", title).Msg("ssh> connected to a Bottlerocket host container")

	self, host, stderr := c.mountNamespaces(shared.BuildSudoCommand(c.Sudo, mountNamespaceProbe))
	if self == "" || host == "" {
		return errors.Newf("the connection reached the admin container of a Bottlerocket host (%s), not the host. "+
			"Scanning the container would report its own files and services as the host's. "+
			"To scan the host, connect with root in the container: use --sudo or connect as root%s",
			title, stderrSuffix(stderr))
	}

	c.bottlerocket = &bottlerocketHost{title: title}
	if self == host {
		log.Debug().Msg("ssh> the elevation already runs commands in the Bottlerocket host's namespaces")
		return nil
	}

	entered, pid1, stderr := c.mountNamespaces(shared.BuildHostNamespacesCommand(c.Sudo, bottlerocketAdminShell, mountNamespaceProbe+" < /dev/null"))
	if entered == "" || entered != pid1 || entered != host {
		c.bottlerocket = nil
		return errors.Newf("the connection reached the admin container of a Bottlerocket host (%s), "+
			"but could not run commands in the host's namespaces with nsenter and %s%s",
			title, bottlerocketAdminShell, stderrSuffix(stderr))
	}
	c.bottlerocket.enter = true
	log.Debug().Str("host", title).Msg("ssh> running commands in the Bottlerocket host's namespaces, as sheltie does")
	return nil
}

// mountNamespaces runs a command that prints two mount namespaces, the
// command's own and PID 1's. Both are empty when the command fails.
func (c *Connection) mountNamespaces(command string) (self string, pid1 string, stderr string) {
	out, err := c.runRaw(command)
	if err != nil || out == nil {
		if err != nil {
			stderr = err.Error()
		}
		return "", "", stderr
	}
	errOut, _ := io.ReadAll(out.Stderr)
	stderr = string(errOut)
	if out.ExitStatus != 0 {
		return "", "", stderr
	}
	stdout, _ := io.ReadAll(out.Stdout)
	lines := strings.Fields(string(stdout))
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "mnt:") || !strings.HasPrefix(lines[1], "mnt:") {
		return "", "", stderr
	}
	return lines[0], lines[1], stderr
}

func stderrSuffix(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	return " (" + stderr + ")"
}

// parseOsRelease reads the KEY=value lines of an os-release file. Values may
// be quoted.
func parseOsRelease(content string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || key == "" || strings.HasPrefix(key, "#") {
			continue
		}
		res[key] = strings.Trim(value, `"'`)
	}
	return res
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/ssh/cat"
)

const (
	hostOsRelease = `NAME=Bottlerocket
ID=bottlerocket
VERSION="1.66.0 (aws-k8s-1.35)"
PRETTY_NAME="Bottlerocket OS 1.66.0 (aws-k8s-1.35)"
VERSION_ID=1.66.0
`
	containerMnt = "mnt:[4026532240]"
	hostMnt      = "mnt:[4026531841]"
)

// bottlerocketTarget answers the commands a connection runs, by exact command line,
// and records them in order.
type bottlerocketTarget struct {
	answers map[string]shared.Command
	ran     []string
}

func (f *bottlerocketTarget) run(command string) (*shared.Command, error) {
	f.ran = append(f.ran, command)
	res := shared.Command{Command: command, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	a, ok := f.answers[command]
	if !ok {
		res.ExitStatus = 127
		res.Stderr = bytes.NewBufferString("unexpected command")
		return &res, nil
	}
	res.ExitStatus = a.ExitStatus
	if a.Stdout != nil {
		res.Stdout = a.Stdout
	}
	if a.Stderr != nil {
		res.Stderr = a.Stderr
	}
	return &res, nil
}

func out(stdout string) shared.Command {
	return shared.Command{Stdout: bytes.NewBufferString(stdout)}
}

func failed(exit int, stderr string) shared.Command {
	return shared.Command{ExitStatus: exit, Stderr: bytes.NewBufferString(stderr)}
}

func newBottlerocketConnection(sudo *inventory.Sudo, answers map[string]shared.Command) (*Connection, *bottlerocketTarget) {
	target := &bottlerocketTarget{answers: answers}
	return &Connection{Sudo: sudo, rawRunner: target.run}, target
}

var activeSudo = &inventory.Sudo{Active: true, Executable: "sudo"}

func TestBottlerocketNotDetectedElsewhere(t *testing.T) {
	conn, target := newBottlerocketConnection(activeSudo, map[string]shared.Command{
		bottlerocketProbe: failed(1, "cat: /.bottlerocket/rootfs/usr/lib/os-release: No such file or directory"),
	})
	require.NoError(t, conn.detectBottlerocketAdminContainer())
	assert.False(t, conn.BottlerocketAdminContainer())
	assert.Equal(t, []string{bottlerocketProbe}, target.ran, "one probe on other targets")

	// commands keep the plain elevation
	_, err := conn.RunCommand("id -u")
	require.NoError(t, err)
	assert.Equal(t, "sudo id -u", target.ran[len(target.ran)-1])
}

// Another distribution mounted at the same path is not Bottlerocket.
func TestBottlerocketProbeNeedsBottlerocketID(t *testing.T) {
	conn, target := newBottlerocketConnection(activeSudo, map[string]shared.Command{
		bottlerocketProbe: out("NAME=\"Amazon Linux\"\nID=\"amzn\"\n"),
	})
	require.NoError(t, conn.detectBottlerocketAdminContainer())
	assert.False(t, conn.BottlerocketAdminContainer())
	assert.Len(t, target.ran, 1)
}

func TestBottlerocketAdminContainerEntersHost(t *testing.T) {
	enter := "sudo nsenter -t 1 -a -- /proc/$$/root/opt/bin/bash -c 'readlink /proc/self/ns/mnt /proc/1/ns/mnt < /dev/null'"
	conn, target := newBottlerocketConnection(activeSudo, map[string]shared.Command{
		bottlerocketProbe:               out(hostOsRelease),
		"sudo " + mountNamespaceProbe:   out(containerMnt + "\n" + hostMnt + "\n"),
		enter:                           out(hostMnt + "\n" + hostMnt + "\n"),
		"sudo nsenter -t 1 -a -- id -u": out("0\n"),
	})
	require.NoError(t, conn.detectBottlerocketAdminContainer())
	assert.True(t, conn.BottlerocketAdminContainer())
	assert.True(t, conn.entersHost())
	assert.Equal(t, []string{bottlerocketProbe, "sudo " + mountNamespaceProbe, enter}, target.ran)

	// every later command runs in the host's namespaces
	res, err := conn.RunCommand("id -u")
	require.NoError(t, err)
	assert.Equal(t, 0, res.ExitStatus)
	assert.Equal(t, "sudo nsenter -t 1 -a -- id -u", target.ran[len(target.ran)-1])

	// files are read with commands, not over sftp as the user
	assert.IsType(t, &cat.Fs{}, conn.FileSystem())
}

// Connected as root, no elevation is needed to enter the host.
func TestBottlerocketAdminContainerAsRoot(t *testing.T) {
	enter := "nsenter -t 1 -a -- /proc/$$/root/opt/bin/bash -c 'readlink /proc/self/ns/mnt /proc/1/ns/mnt < /dev/null'"
	conn, _ := newBottlerocketConnection(nil, map[string]shared.Command{
		bottlerocketProbe:   out(hostOsRelease),
		mountNamespaceProbe: out(containerMnt + "\n" + hostMnt + "\n"),
		enter:               out(hostMnt + "\n" + hostMnt + "\n"),
	})
	require.NoError(t, conn.detectBottlerocketAdminContainer())
	assert.True(t, conn.entersHost())
}

// Without root, the probe cannot read PID 1's mount namespace, and a scan of
// the container would report its state as the host's.
func TestBottlerocketAdminContainerWithoutRootFails(t *testing.T) {
	conn, target := newBottlerocketConnection(nil, map[string]shared.Command{
		bottlerocketProbe:   out(hostOsRelease),
		mountNamespaceProbe: failed(1, "readlink: /proc/1/ns/mnt: Permission denied\n"),
	})
	err := conn.detectBottlerocketAdminContainer()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin container of a Bottlerocket host (Bottlerocket OS 1.66.0 (aws-k8s-1.35))")
	assert.Contains(t, err.Error(), "use --sudo or connect as root")
	assert.Contains(t, err.Error(), "Permission denied")
	assert.False(t, conn.BottlerocketAdminContainer())
	assert.Len(t, target.ran, 2)
}

// An elevation that already runs commands in the host's namespaces, such as a
// wrapper around sheltie, is kept as it is.
func TestBottlerocketElevationAlreadyOnHost(t *testing.T) {
	wrapper := &inventory.Sudo{Active: true, Executable: "sudo /usr/local/bin/host-wrapper"}
	conn, target := newBottlerocketConnection(wrapper, map[string]shared.Command{
		bottlerocketProbe: out(hostOsRelease),
		"sudo /usr/local/bin/host-wrapper " + mountNamespaceProbe: out(hostMnt + "\n" + hostMnt + "\n"),
		"sudo /usr/local/bin/host-wrapper id -u":                  out("0\n"),
	})
	require.NoError(t, conn.detectBottlerocketAdminContainer())
	assert.True(t, conn.BottlerocketAdminContainer())
	assert.False(t, conn.entersHost())
	assert.Len(t, target.ran, 2)

	_, err := conn.RunCommand("id -u")
	require.NoError(t, err)
	assert.Equal(t, "sudo /usr/local/bin/host-wrapper id -u", target.ran[len(target.ran)-1])
}

// When a command line cannot reach the host, for example because the
// container has no static bash, the connection fails instead of scanning the
// container.
func TestBottlerocketCannotEnterHost(t *testing.T) {
	enter := "sudo nsenter -t 1 -a -- /proc/$$/root/opt/bin/bash -c 'readlink /proc/self/ns/mnt /proc/1/ns/mnt < /dev/null'"
	conn, _ := newBottlerocketConnection(activeSudo, map[string]shared.Command{
		bottlerocketProbe:             out(hostOsRelease),
		"sudo " + mountNamespaceProbe: out(containerMnt + "\n" + hostMnt + "\n"),
		enter:                         failed(127, "nsenter: failed to execute /proc/1234/root/opt/bin/bash: No such file or directory\n"),
	})
	err := conn.detectBottlerocketAdminContainer()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not run commands in the host's namespaces")
	assert.Contains(t, err.Error(), "No such file or directory")
	assert.False(t, conn.BottlerocketAdminContainer())
	assert.False(t, conn.entersHost())
}

// A command line that still lands in the container's mount namespace did not
// reach the host.
func TestBottlerocketEnteredNamespaceMustBeTheHost(t *testing.T) {
	enter := "sudo nsenter -t 1 -a -- /proc/$$/root/opt/bin/bash -c 'readlink /proc/self/ns/mnt /proc/1/ns/mnt < /dev/null'"
	conn, _ := newBottlerocketConnection(activeSudo, map[string]shared.Command{
		bottlerocketProbe:             out(hostOsRelease),
		"sudo " + mountNamespaceProbe: out(containerMnt + "\n" + hostMnt + "\n"),
		enter:                         out(containerMnt + "\n" + hostMnt + "\n"),
	})
	require.Error(t, conn.detectBottlerocketAdminContainer())
	assert.False(t, conn.BottlerocketAdminContainer())
}

func TestParseOsRelease(t *testing.T) {
	osr := parseOsRelease(hostOsRelease + "# comment\nEMPTY=\nQUOTED='single'\n")
	assert.Equal(t, "bottlerocket", osr["ID"])
	assert.Equal(t, "Bottlerocket OS 1.66.0 (aws-k8s-1.35)", osr["PRETTY_NAME"])
	assert.Equal(t, "single", osr["QUOTED"])
	assert.Equal(t, "", osr["EMPTY"])
	_, comment := osr["# comment"]
	assert.False(t, comment)
}

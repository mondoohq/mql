// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// sshMockConn is a mock connection that announces an SSH server version and
// records the commands it runs.
type sshMockConn struct {
	*mock.Connection
	serverVersion string
	commands      []string
}

func (c *sshMockConn) ServerVersion() string { return c.serverVersion }

func (c *sshMockConn) Type() shared.ConnectionType { return shared.Type_SSH }

func (c *sshMockConn) RunCommand(command string) (*shared.Command, error) {
	c.commands = append(c.commands, command)
	return c.Connection.RunCommand(command)
}

func (c *sshMockConn) unameCalls() int {
	n := 0
	for _, cmd := range c.commands {
		if strings.HasPrefix(cmd, "uname") {
			n++
		}
	}
	return n
}

func newSSHMockConn(t *testing.T, path, serverVersion string) *sshMockConn {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath(path))
	require.NoError(t, err)
	return &sshMockConn{Connection: conn, serverVersion: serverVersion}
}

func TestDetectOSWindowsSSHServer(t *testing.T) {
	t.Run("OpenSSH for Windows resolves Windows without unix probes", func(t *testing.T) {
		conn := newSSHMockConn(t, "./testdata/detect-windows2022.toml", "SSH-2.0-OpenSSH_for_Windows_8.1")

		pf, ok := DetectOS(conn)
		require.True(t, ok)
		assert.Equal(t, "windows", pf.Name)
		assert.Equal(t, "20348", pf.Version)
		assert.Equal(t, []string{"windows", "os"}, pf.Family)
		assert.Equal(t, 0, conn.unameCalls(), "no uname probes on a Windows SSH server")
	})

	t.Run("the result matches the full resolution", func(t *testing.T) {
		hinted := newSSHMockConn(t, "./testdata/detect-windows2022.toml", "SSH-2.0-OpenSSH_for_Windows_8.1")
		plain := newSSHMockConn(t, "./testdata/detect-windows2022.toml", "SSH-2.0-OpenSSH_9.6")

		got, ok := DetectOS(hinted)
		require.True(t, ok)
		want, ok := DetectOS(plain)
		require.True(t, ok)
		assert.Equal(t, want, got)
		assert.NotZero(t, plain.unameCalls(), "other servers still go through the unix families first")
	})

	t.Run("falls back to the full tree when Windows detection fails", func(t *testing.T) {
		conn := newSSHMockConn(t, "./testdata/detect-ubuntu2204.toml", "SSH-2.0-OpenSSH_for_Windows_8.1")

		pf, ok := DetectOS(conn)
		require.True(t, ok)
		assert.Equal(t, "ubuntu", pf.Name)
		assert.Contains(t, pf.Family, "linux")
	})
}

// versionOnlyConn announces an SSH server version without being an SSH
// connection.
type versionOnlyConn struct{ *mock.Connection }

func (versionOnlyConn) ServerVersion() string { return "SSH-2.0-OpenSSH_for_Windows_8.1" }

func TestIsWindowsSSHServerOnlyForSSH(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/detect-windows2022.toml"))
	require.NoError(t, err)
	assert.False(t, isWindowsSSHServer(versionOnlyConn{conn}), "only an SSH connection can be an OpenSSH for Windows server")
	assert.True(t, isWindowsSSHServer(&sshMockConn{Connection: conn, serverVersion: "SSH-2.0-OpenSSH_for_Windows_8.1"}))
	assert.False(t, isWindowsSSHServer(&sshMockConn{Connection: conn, serverVersion: "SSH-2.0-OpenSSH_9.6"}))
}

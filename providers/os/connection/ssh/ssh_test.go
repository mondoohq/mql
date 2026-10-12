// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"golang.org/x/crypto/ssh"
)

func TestSSHDefaultSettings(t *testing.T) {
	conn := &Connection{
		conf: &inventory.Config{
			Sudo: &inventory.Sudo{
				Active: true,
			},
		},
	}
	conn.setDefaultSettings()
	assert.Equal(t, int32(22), conn.conf.Port)
	// the executable is resolved against the target after connecting
	assert.Equal(t, "", conn.conf.Sudo.Executable)
}

func TestVerifyError(t *testing.T) {
	sudo := &inventory.Sudo{Active: true, Executable: "sudo"}
	doas := &inventory.Sudo{Active: true, Executable: "doas"}

	assert.EqualError(t, verifyError(sudo, "sh: 1: sudo: not found\n"), "sudo command is missing on target")
	assert.EqualError(t, verifyError(doas, "sh: doas: not found\n"), "doas command is missing on target")
	assert.EqualError(t, verifyError(sudo, "sudo: a password is required\n"),
		"could not establish connection: sudo password is not supported yet, configure password-less sudo")
	assert.EqualError(t, verifyError(doas, "doas: Authentication required\n"),
		"could not establish connection: doas password is not supported yet, configure password-less doas")
	assert.EqualError(t, verifyError(doas, "doas: a tty is required\n"),
		"could not establish connection: doas password is not supported yet, configure password-less doas")
	assert.EqualError(t, verifyError(doas, "doas: Operation not permitted\n"),
		"could not establish connection: doas: Operation not permitted\n")
}

func TestSSHProviderError(t *testing.T) {
	_, err := NewConnection(0, &inventory.Config{Type: shared.Type_Local.String(), Host: "example.local"}, &inventory.Asset{})
	assert.Equal(t, "provider type does not match", err.Error())
}

func TestSSHAuthError(t *testing.T) {
	_, err := NewConnection(0, &inventory.Config{Type: shared.Type_SSH.String(), Host: "example.local"}, &inventory.Asset{})
	assert.True(t,
		// local testing if ssh agent is available
		err.Error() == "dial tcp: lookup example.local: no such host" ||
			// local testing without ssh agent
			err.Error() == "no authentication method defined")
}

// helper to start a fake SSH server with a custom banner
func startMockSSHServer(t *testing.T, banner string) (addr string, closeFn func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// simulate SSH banner
		_, _ = conn.Write([]byte(banner + "\r\n"))
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

func TestServerSupportsHybridKEX(t *testing.T) {
	tests := []struct {
		name         string
		banner       string
		expectHybrid bool
	}{
		{
			name:         "OpenSSH 9.9 detected",
			banner:       "SSH-2.0-OpenSSH_9.9",
			expectHybrid: true,
		},
		{
			name:         "OpenSSH 9.7 (no hybrid)",
			banner:       "SSH-2.0-OpenSSH_9.7",
			expectHybrid: false,
		},
		{
			name:         "Non-OpenSSH server",
			banner:       "SSH-2.0-CustomSSH_1.0",
			expectHybrid: false,
		},
		{
			name:         "Malformed banner",
			banner:       "garbage",
			expectHybrid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, shutdown := startMockSSHServer(t, tt.banner)
			defer shutdown()

			got, err := serverSupportsHybridKEX(addr)
			require.Nil(t, err)
			assert.Equal(t, tt.expectHybrid, got)
		})
	}
}

func TestServerSupportsHybridKEX_ServerUnreachable(t *testing.T) {
	_, err := serverSupportsHybridKEX("127.0.0.1:9")
	require.NotNil(t, err)
}

type countingCloser struct{ closed int }

func (c *countingCloser) Close() error {
	c.closed++
	return nil
}

// What the connection set up besides the SSH client, such as an SSM session,
// ends with the connection, once.
func TestCloseClosesWhatTheConnectionSetUp(t *testing.T) {
	closer := &countingCloser{}
	conn := &Connection{closers: []io.Closer{closer}}
	conn.Close()
	assert.Equal(t, 1, closer.closed)
	conn.Close()
	assert.Equal(t, 1, closer.closed)
}

// Commands that see the same client fail reconnect once; the others use the
// new client. Every reconnect over an SSM session starts a session of its own.
func TestReconnectAfterOncePerFailedClient(t *testing.T) {
	failed := &ssh.Client{}
	conn := &Connection{SSHClient: failed}
	var reconnects atomic.Int32
	conn.reconnectHook = func() error {
		reconnects.Add(1)
		time.Sleep(50 * time.Millisecond)
		conn.SSHClient = &ssh.Client{}
		return nil
	}

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, conn.reconnectAfter(failed))
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), reconnects.Load())
	assert.NotSame(t, failed, conn.currentClient())

	// the new client failing reconnects again
	assert.NoError(t, conn.reconnectAfter(conn.currentClient()))
	assert.Equal(t, int32(2), reconnects.Load())
}

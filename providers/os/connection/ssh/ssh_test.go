// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"sync"
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
	assert.EqualError(t, verifyError(sudo, "sudo: A terminal is required to authenticate\n"),
		"could not establish connection: sudo password is not supported yet, configure password-less sudo")
	assert.EqualError(t, verifyError(doas, "doas: Authentication required\n"),
		"could not establish connection: doas password is not supported yet, configure password-less doas")
	assert.EqualError(t, verifyError(doas, "doas: a tty is required\n"),
		"could not establish connection: doas password is not supported yet, configure password-less doas")
	assert.EqualError(t, verifyError(sudo, "sudo: sorry, you must have a tty to run sudo\n"),
		"could not establish connection: sudo requires a terminal (Defaults requiretty), which a scan does not have; exempt the login user with Defaults:<user> !requiretty")
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

func TestSSHConnectTimeout(t *testing.T) {
	t.Setenv("MONDOO_SSH_CONNECT_TIMEOUT", "")
	got, err := sshConnectTimeout(nil)
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, got)
	t.Setenv("MONDOO_SSH_CONNECT_TIMEOUT", "45s")
	got, err = sshConnectTimeout(nil)
	require.NoError(t, err)
	assert.Equal(t, 45*time.Second, got)
	got, err = sshConnectTimeout(map[string]string{"ssh_connect_timeout": "2m"})
	require.NoError(t, err)
	assert.Equal(t, 2*time.Minute, got)
	for _, value := range []string{"0", "0s", "-1s", "invalid"} {
		_, err := sshConnectTimeout(map[string]string{"ssh_connect_timeout": value})
		assert.Error(t, err, value)
	}
}

func TestServerSupportsHybridKEXDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	peer := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			peer <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = serverSupportsHybridKEXContext(ctx, ln.Addr().String())
	require.Error(t, err)
	assert.Less(t, time.Since(start), 2*time.Second)
	select {
	case conn := <-peer:
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err := io.ReadAll(conn)
		assert.NoError(t, err, "the timed-out probe must close its socket")
	case <-time.After(time.Second):
		t.Fatal("probe did not connect")
	}
}

func startupSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

func TestDialSSHContextDeadline(t *testing.T) {
	for _, authStalls := range []bool{false, true} {
		name := "handshake"
		if authStalls {
			name = "authentication"
		}
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			peer := make(chan net.Conn, 1)
			release := make(chan struct{})
			defer close(release)
			signer := startupSigner(t)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				peer <- conn
				if authStalls {
					cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
						<-release
						return nil, nil
					}}
					cfg.AddHostKey(signer)
					server, _, _, _ := ssh.NewServerConn(conn, cfg)
					if server != nil {
						server.Close()
					}
				} else {
					_, _ = io.WriteString(conn, "SSH-2.0-stalled-peer\r\n")
					<-release
				}
				conn.Close()
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			started := time.Now()
			client, err := dialSSHContext(ctx, ln.Addr().String(), &ssh.ClientConfig{
				User: "test", Auth: []ssh.AuthMethod{ssh.Password("test")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			})
			require.Error(t, err)
			assert.Nil(t, client)
			assert.Less(t, time.Since(started), 2*time.Second)
			select {
			case conn := <-peer:
				conn.Close()
			case <-time.After(time.Second):
				t.Fatal("client did not connect")
			}
		})
	}
}

func TestDialSSHContextClearsStartupDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	signer := startupSigner(t)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		cfg := &ssh.ServerConfig{NoClientAuth: true}
		cfg.AddHostKey(signer)
		server, channels, requests, err := ssh.NewServerConn(conn, cfg)
		if err != nil {
			return
		}
		defer server.Close()
		go func() {
			for channel := range channels {
				_ = channel.Reject(ssh.UnknownChannelType, "unused")
			}
		}()
		for req := range requests {
			_ = req.Reply(req.Type == "ping", nil)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	client, err := dialSSHContext(ctx, ln.Addr().String(), &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	require.NoError(t, err)
	defer client.Close()
	cancel()
	// Cancellation after establishment must not close the retained transport.
	ok, _, err := client.SendRequest("ping", true, nil)
	require.NoError(t, err)
	assert.True(t, ok)
	client.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("SSH fixture did not stop")
	}
}

func TestDialSSHContextCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := dialSSHContext(ctx, ln.Addr().String(), &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
		done <- err
	}()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(time.Second):
		t.Fatal("client did not connect")
	}
	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("cancelled handshake did not return")
	}
}

// commandSSHClient speaks real SSH while the handler controls process lifetime.
func commandSSHClient(t *testing.T, handler func(ssh.Channel, string, <-chan struct{})) *ssh.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	signer := startupSigner(t)
	var peerMu sync.Mutex
	var peer net.Conn
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		peerMu.Lock()
		peer = conn
		peerMu.Unlock()
		cfg := &ssh.ServerConfig{NoClientAuth: true}
		cfg.AddHostKey(signer)
		server, channels, requests, err := ssh.NewServerConn(conn, cfg)
		if err != nil {
			conn.Close()
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for offered := range channels {
			channel, requests, err := offered.Accept()
			if err != nil {
				continue
			}
			go func() {
				closed := make(chan struct{})
				defer close(closed)
				for req := range requests {
					if req.Type != "exec" {
						_ = req.Reply(false, nil)
						continue
					}
					var payload struct{ Command string }
					_ = ssh.Unmarshal(req.Payload, &payload)
					_ = req.Reply(true, nil)
					go handler(channel, payload.Command, closed)
				}
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := dialSSHContext(ctx, ln.Addr().String(), &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	require.NoError(t, err)
	t.Cleanup(func() {
		client.Close()
		ln.Close()
		peerMu.Lock()
		if peer != nil {
			peer.Close()
		}
		peerMu.Unlock()
	})
	return client
}
func TestSSHCommandCancellation(t *testing.T) {
	stopped := make(chan struct{})
	client := commandSSHClient(t, func(channel ssh.Channel, command string, closed <-chan struct{}) {
		defer channel.Close()
		if command == "hang" {
			select {
			case <-closed:
				close(stopped)
			case <-time.After(5 * time.Second):
			}
			return
		}
		_, _ = io.WriteString(channel, "ready")
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{0}))
	})
	conn := &Connection{SSHClient: client}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	_, err := conn.RunCommandContext(ctx, "hang")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("cancelled SSH channel remained open")
	}
	res, err := conn.RunCommand("ready")
	require.NoError(t, err)
	got, err := io.ReadAll(res.Stdout)
	require.NoError(t, err)
	assert.Equal(t, "ready", string(got))
}
func TestSSHCommandOutputLimit(t *testing.T) {
	t.Setenv("MONDOO_COMMAND_OUTPUT_LIMIT", "32")
	client := commandSSHClient(t, func(channel ssh.Channel, _ string, _ <-chan struct{}) {
		defer channel.Close()
		_, _ = channel.Write(make([]byte, 4096))
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{0}))
	})
	conn := &Connection{SSHClient: client}
	_, err := conn.RunCommand("large-output")
	assert.ErrorIs(t, err, shared.ErrCommandOutputLimit)
}

// refusingSudo answers like sudo on a host with `Defaults requiretty`, which
// rejects every command run without a terminal.
func refusingSudo(command string) (*shared.Command, error) {
	res := &shared.Command{Command: command, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	if strings.Contains(command, "sudo ") {
		res.ExitStatus = 1
		res.Stderr = bytes.NewBufferString("sudo: sorry, you must have a tty to run sudo\n")
	}
	return res, nil
}

func TestCheckConnectionFailsWhenSudoRefuses(t *testing.T) {
	c := &Connection{conf: &inventory.Config{}, rawRunner: refusingSudo}
	c.Sudo = &inventory.Sudo{Active: true, Executable: "sudo"}

	err := c.checkConnection()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sudo requires a terminal")
}

func TestCheckConnectionWithoutSudo(t *testing.T) {
	c := &Connection{conf: &inventory.Config{}, rawRunner: refusingSudo}
	require.NoError(t, c.checkConnection())

	// without elevation a failed check is only logged: the files and
	// commands that do not need the check command still work
	failing := func(command string) (*shared.Command, error) {
		return &shared.Command{Command: command, ExitStatus: 127, Stdout: &bytes.Buffer{}, Stderr: bytes.NewBufferString("sh: echo: not found\n")}, nil
	}
	c = &Connection{conf: &inventory.Config{}, rawRunner: failing}
	require.NoError(t, c.checkConnection())
}

func TestCheckConnectionWithWorkingSudo(t *testing.T) {
	ok := func(command string) (*shared.Command, error) {
		return &shared.Command{Command: command, Stdout: bytes.NewBufferString("hi\n"), Stderr: &bytes.Buffer{}}, nil
	}
	c := &Connection{conf: &inventory.Config{}, rawRunner: ok}
	c.Sudo = &inventory.Sudo{Active: true, Executable: "sudo"}
	require.NoError(t, c.checkConnection())
}

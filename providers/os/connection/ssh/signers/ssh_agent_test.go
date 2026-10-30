// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package signers

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestGetSignersFromSSHAgentContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a Unix agent socket")
	}
	dir, err := os.MkdirTemp("/tmp", "mql-agent-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer ln.Close()
	t.Setenv("SSH_AUTH_SOCK", socket)
	peerDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			peerDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = io.Copy(io.Discard, conn)
		peerDone <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	start := time.Now()
	got := GetSignersFromSSHAgentContext(ctx)
	assert.Empty(t, got)
	assert.Less(t, time.Since(start), time.Second)
	select {
	case err := <-peerDone:
		assert.NoError(t, err, "cancelled agent socket must close")
	case <-time.After(time.Second):
		t.Fatal("agent socket leaked after cancellation")
	}
}

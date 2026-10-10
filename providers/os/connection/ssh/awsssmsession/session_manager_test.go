// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsssmsession

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTerminator struct {
	calls []string
	err   error
}

func (f *fakeTerminator) TerminateSession(_ context.Context, params *ssm.TerminateSessionInput, _ ...func(*ssm.Options)) (*ssm.TerminateSessionOutput, error) {
	f.calls = append(f.calls, aws.ToString(params.SessionId))
	return &ssm.TerminateSessionOutput{}, f.err
}

// startProcess starts a long-running process standing in for the
// session-manager-plugin, reaped as NewAwsSsmSessionConnection reaps it.
func startProcess(t *testing.T) (*exec.Cmd, chan struct{}) {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	require.NoError(t, cmd.Start())
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	return cmd, exited
}

func TestCloseStopsPluginAndTerminatesSession(t *testing.T) {
	cmd, exited := startProcess(t)
	term := &fakeTerminator{}
	conn := &AwsSsmSessionConnection{
		terminator: term,
		session:    &ssm.StartSessionOutput{SessionId: aws.String("user-0123456789abcdef")},
		process:    cmd.Process,
		exited:     exited,
	}

	require.NoError(t, conn.Close())
	assert.Equal(t, []string{"user-0123456789abcdef"}, term.calls)
	select {
	case <-exited:
	default:
		t.Fatal("the plugin process is still running after Close")
	}

	// the provider and a failed reconnect may both close the connection
	require.NoError(t, conn.Close())
	assert.Len(t, term.calls, 1, "the session is terminated once")
}

func TestCloseReportsTerminateError(t *testing.T) {
	term := &fakeTerminator{err: errors.New("AccessDeniedException")}
	conn := &AwsSsmSessionConnection{
		terminator: term,
		session:    &ssm.StartSessionOutput{SessionId: aws.String("user-0123456789abcdef")},
	}
	err := conn.Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "terminate ssm session user-0123456789abcdef")
	assert.Contains(t, err.Error(), "AccessDeniedException")
}

// A plugin that already exited is not an error: the session must still be
// terminated.
func TestCloseAfterPluginExited(t *testing.T) {
	cmd, exited := startProcess(t)
	require.NoError(t, cmd.Process.Kill())
	<-exited

	term := &fakeTerminator{}
	conn := &AwsSsmSessionConnection{
		terminator: term,
		session:    &ssm.StartSessionOutput{SessionId: aws.String("s")},
		process:    cmd.Process,
		exited:     exited,
	}
	require.NoError(t, conn.Close())
	assert.Equal(t, []string{"s"}, term.calls)
}

func freePort(t *testing.T) string {
	t.Helper()
	port, err := GetAvailablePort()
	require.NoError(t, err)
	return strconv.Itoa(port)
}

func TestWaitForLocalPortWaitsForTheListener(t *testing.T) {
	addr := LocalAddress(freePort(t))
	go func() {
		time.Sleep(300 * time.Millisecond)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		t.Cleanup(func() { l.Close() })
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	require.NoError(t, WaitForLocalPort(addr, make(chan struct{}), 5*time.Second))
}

func TestWaitForLocalPortTimesOut(t *testing.T) {
	addr := LocalAddress(freePort(t))
	err := WaitForLocalPort(addr, make(chan struct{}), 300*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not listen on "+addr)
}

func TestWaitForLocalPortStopsWhenThePluginExits(t *testing.T) {
	exited := make(chan struct{})
	close(exited)
	start := time.Now()
	err := WaitForLocalPort(LocalAddress(freePort(t)), exited, 10*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exited before it listened")
	assert.Less(t, time.Since(start), 5*time.Second)
}

// The plugin listens on IPv4 only; "localhost" can resolve to ::1 first.
func TestLocalAddressIsIPv4Loopback(t *testing.T) {
	assert.Equal(t, "127.0.0.1:2222", LocalAddress("2222"))
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package local

import (
	"context"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCommandRunnerCancelsProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	runner := &CommandRunner{Shell: []string{"sh", "-c"}}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := runner.ExecContext(ctx, "sleep 10 & child=$!; echo $child > '"+pidFile+"'; wait $child", nil)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(started), 2*time.Second)
	raw, err := os.ReadFile(pidFile)
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	// SIGKILL to the process group is delivered asynchronously: on a loaded
	// machine the child can still be running right after ExecContext returns.
	// Wait for it to stop executing instead of sampling its state once. A
	// killed child can briefly remain a zombie until the OS reaps it, so
	// inspect its process state rather than kill(0) alone.
	if _, err := os.Stat("/proc/self/stat"); err == nil {
		state, ok := waitProcStopped(pid, 2*time.Second)
		assert.True(t, ok, "child %d still executing after cancellation, last state %q", pid, state)
	} else {
		// macOS has no procfs; a fully reaped child returns ESRCH.
		deadline := time.Now().Add(time.Second)
		for syscall.Kill(pid, 0) == nil && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		assert.True(t, errors.Is(syscall.Kill(pid, 0), syscall.ESRCH))
	}
}

// procState returns the state field of /proc/<pid>/stat. The comm field is
// parenthesized and may itself contain spaces or parens, so the state is the
// first field after the last ')'. gone is true once the process is reaped.
func procState(pid int) (state string, gone bool) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", errors.Is(err, os.ErrNotExist)
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return s, false
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) == 0 {
		return s, false
	}
	return fields[0], false
}

// waitProcStopped polls until the process is a zombie (Z), dead (X) or reaped,
// and reports the last observed state.
func waitProcStopped(pid int, timeout time.Duration) (last string, stopped bool) {
	deadline := time.Now().Add(timeout)
	for {
		state, gone := procState(pid)
		if gone {
			return "reaped", true
		}
		last = state
		if state == "Z" || state == "X" {
			return last, true
		}
		if !time.Now().Before(deadline) {
			return last, false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCommandRunnerBoundsOutput(t *testing.T) {
	t.Setenv("MONDOO_COMMAND_OUTPUT_LIMIT", "32")
	runner := &CommandRunner{Shell: []string{"sh", "-c"}}
	_, err := runner.Exec("while :; do printf '0123456789abcdef'; done", nil)
	require.ErrorIs(t, err, shared.ErrCommandOutputLimit)
	got, err := io.ReadAll(runner.Stdout)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(got), 32)
}
func TestCommandRunnerBoundsInheritedPipeDrain(t *testing.T) {
	runner := &CommandRunner{Shell: []string{"sh", "-c"}}
	started := time.Now()
	_, err := runner.Exec("sleep 10 & printf ready", nil)
	require.Error(t, err, "a child holding stdout open cannot produce successful partial output")
	assert.Less(t, time.Since(started), 3*time.Second)
}
func TestCommandRunnerLegacyTimeout(t *testing.T) {
	t.Setenv("MONDOO_COMMAND_TIMEOUT", "75ms")
	runner := &CommandRunner{Shell: []string{"sh", "-c"}}
	_, err := runner.Exec("sleep 10", nil)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

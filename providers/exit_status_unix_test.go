// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package providers

import (
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatExitStatus_ExitCode(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 2")
	_ = cmd.Run()
	require.NotNil(t, cmd.ProcessState)
	assert.Equal(t, "code:2", formatExitStatus(cmd.ProcessState))
}

func TestFormatExitStatus_CleanExit(t *testing.T) {
	cmd := exec.Command("true")
	require.NoError(t, cmd.Run())
	assert.Equal(t, "code:0", formatExitStatus(cmd.ProcessState))
}

func TestFormatExitStatus_Signal(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	require.NoError(t, cmd.Start())
	require.NoError(t, cmd.Process.Kill()) // SIGKILL, same as the OOM killer
	_ = cmd.Wait()
	require.NotNil(t, cmd.ProcessState)
	assert.Equal(t, "signal:SIGKILL", formatExitStatus(cmd.ProcessState))
}

func TestFormatExitStatus_Nil(t *testing.T) {
	assert.Equal(t, "unknown", formatExitStatus(nil))
}

func TestMaxRSSBytes(t *testing.T) {
	cmd := exec.Command("true")
	require.NoError(t, cmd.Run())
	assert.Greater(t, maxRSSBytes(cmd.ProcessState), int64(0))
	assert.Zero(t, maxRSSBytes(nil))
}

func TestProcessTracker_NoSubprocess(t *testing.T) {
	// Untracked (builtin providers, tests): no state, no panic, no wait.
	tracker := &processTracker{}
	exited, ps := tracker.exitInfo()
	assert.False(t, exited)
	assert.Nil(t, ps)

	p := &RunningProvider{}
	exited, ps = p.awaitExit(time.Second)
	assert.False(t, exited)
	assert.Nil(t, ps)
}

func TestAwaitExit_GraceIsMemoized(t *testing.T) {
	// A tracker whose subprocess never exits: the first awaitExit pays the
	// grace period, subsequent calls must return immediately.
	cmd := exec.Command("sleep", "30")
	require.NoError(t, cmd.Start())
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	p := &RunningProvider{proc: &processTracker{}}
	p.proc.track(nil, cmd) // nil client → exitInfo always reports running
	_, _ = p.awaitExit(30 * time.Millisecond)
	require.True(t, p.exitGraceExpired.Load())

	start := time.Now()
	exited, ps := p.awaitExit(30 * time.Millisecond)
	assert.False(t, exited)
	assert.Nil(t, ps)
	assert.Less(t, time.Since(start), 25*time.Millisecond)
}

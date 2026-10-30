// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package local

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLocalCommandWindowsNormal(t *testing.T) {
	runner := &CommandRunner{Shell: []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-Command"}}
	res, err := runner.Exec("cmd.exe /c echo ready", nil)
	require.NoError(t, err)
	got, err := io.ReadAll(res.Stdout)
	require.NoError(t, err)
	assert.Equal(t, "ready", strings.TrimSpace(string(got)))
	assert.Zero(t, res.ExitStatus)
}
func TestLocalCommandWindowsTimeout(t *testing.T) {
	t.Setenv("MONDOO_COMMAND_TIMEOUT", "500ms")
	runner := &CommandRunner{Shell: []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-Command"}}
	started := time.Now()
	_, err := runner.Exec("Start-Sleep -Seconds 20", nil)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(started), 3*time.Second)
}
func TestLocalCommandWindowsProcessTree(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	script := "$p = Start-Process powershell.exe -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 20' -PassThru; [IO.File]::WriteAllText('" + strings.ReplaceAll(pidFile, "'", "''") + "', [string]$p.Id); Start-Sleep -Seconds 20"
	runner := &CommandRunner{Shell: []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-Command"}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := runner.ExecContext(ctx, script, nil)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	raw, err := os.ReadFile(pidFile)
	require.NoError(t, err, "fixture must launch its child before the deadline")
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err == nil {
		defer func() { assert.NoError(t, windows.CloseHandle(handle)) }()
		var code uint32
		require.NoError(t, windows.GetExitCodeProcess(handle, &code))
		assert.NotEqual(t, uint32(259), code, "descendant is still running after cancellation")
	} else {
		assert.ErrorIs(t, err, windows.ERROR_INVALID_PARAMETER)
	}
}
func TestLocalCommandWindowsOutput(t *testing.T) {
	t.Setenv("MONDOO_COMMAND_OUTPUT_LIMIT", "1024")
	runner := &CommandRunner{Shell: []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-Command"}}
	_, err := runner.Exec("[Console]::Out.Write(('x' * 4096))", nil)
	assert.ErrorIs(t, err, shared.ErrCommandOutputLimit)
}

// The fixture's parent starts a descendant immediately, without PowerShell's
// startup delay masking a process/job assignment race.
func TestLocalCommandWindowsProcessHelper(t *testing.T) {
	switch os.Getenv("MQL_COMMAND_PROCESS_HELPER") {
	case "child":
		time.Sleep(20 * time.Second)
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=^TestLocalCommandWindowsProcessHelper$")
		child.Env = append(os.Environ(), "MQL_COMMAND_PROCESS_HELPER=child")
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv("MQL_COMMAND_CHILD_PID"), []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
			os.Exit(3)
		}
		_ = child.Wait()
	}
}
func TestLocalCommandWindowsSuspendsUntilAssigned(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "fast-child.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLocalCommandWindowsProcessHelper$")
	cmd.Env = append(os.Environ(), "MQL_COMMAND_PROCESS_HELPER=parent", "MQL_COMMAND_CHILD_PID="+pidFile)
	process, err := newCommandProcess(cmd)
	require.NoError(t, err)
	defer process.close()
	require.NoError(t, cmd.Start())
	// Deliberately widen the exact race between Start and job assignment.
	time.Sleep(200 * time.Millisecond)
	_, err = os.Stat(pidFile)
	require.True(t, os.IsNotExist(err), "child executed before job assignment")
	require.NoError(t, process.started())
	require.Eventually(t, func() bool { _, err := os.Stat(pidFile); return err == nil }, 2*time.Second, 10*time.Millisecond)
	raw, err := os.ReadFile(pidFile)
	require.NoError(t, err)
	pid, err := strconv.Atoi(string(raw))
	require.NoError(t, err)
	cancel()
	require.Error(t, cmd.Wait())
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err == nil {
		defer func() { assert.NoError(t, windows.CloseHandle(handle)) }()
		var code uint32
		require.NoError(t, windows.GetExitCodeProcess(handle, &code))
		assert.NotEqual(t, uint32(259), code, "fast descendant escaped cancellation job")
	} else {
		assert.ErrorIs(t, err, windows.ERROR_INVALID_PARAMETER)
	}
}

func TestLocalCommandWindowsCancellationBeforeAssignment(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "never-started-child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLocalCommandWindowsProcessHelper$")
	cmd.Env = append(os.Environ(), "MQL_COMMAND_PROCESS_HELPER=parent", "MQL_COMMAND_CHILD_PID="+pidFile)
	process, err := newCommandProcess(cmd)
	require.NoError(t, err)
	defer process.close()
	require.NoError(t, cmd.Start())
	cancel()
	require.Error(t, cmd.Wait())
	_, err = os.Stat(pidFile)
	assert.True(t, os.IsNotExist(err), "cancelled suspended parent must never execute")
}

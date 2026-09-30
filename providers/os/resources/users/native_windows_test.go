// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package users

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// The native users equal what the PowerShell path reports on the same host,
// for the fields users.list uses: name, SID, home and enabled.
func TestNativeUsersMatchPowerShell(t *testing.T) {
	// The script is too long for -EncodedCommand; run it from a file, as the
	// staged PowerShell path does.
	script := filepath.Join(t.TempDir(), "users.ps1")
	require.NoError(t, os.WriteFile(script, []byte(getLocalUsersScript), 0o600))
	stdout, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script).Output()
	require.NoError(t, err)
	ps, err := powershell.UnmarshalList[WindowsLocalUser](stdout)
	require.NoError(t, err)

	native, err := nativeWindowsLocalUsers()
	require.NoError(t, err)

	want := map[string]*User{}
	for _, u := range ps {
		want[u.SID.Value] = winToUser(u)
	}
	got := map[string]*User{}
	for _, u := range native {
		got[u.SID.Value] = winToUser(u)
	}
	require.Equal(t, len(want), len(got))
	for sid, w := range want {
		g, ok := got[sid]
		require.True(t, ok, sid)
		assert.Equal(t, w, g, sid)
	}
}

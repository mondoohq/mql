// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package services

import (
	"bytes"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The native list and the PowerShell path's list agree on the same machine:
// the same services, and for each the start type (enabled), the description
// and, where it is not changing right now, the state.
func TestNativeWindowsServicesMatchesPowerShell(t *testing.T) {
	native, err := nativeWindowsServices()
	require.NoError(t, err)
	require.NotEmpty(t, native)

	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsServicesScript).Output()
	require.NoError(t, err)
	ps, err := ParseWindowsService(bytes.NewReader(out))
	require.NoError(t, err)

	byName := map[string]*Service{}
	for _, s := range ps {
		byName[s.Name] = s
	}
	assert.Equal(t, len(ps), len(native), "number of services")

	for _, n := range native {
		p, ok := byName[n.Name]
		if !assert.Truef(t, ok, "%s is listed natively but not by Get-Service", n.Name) {
			continue
		}
		if n.ConfigUnknown {
			t.Logf("%s: configuration not readable natively; enabled and description are null", n.Name)
			continue
		}
		assert.Equalf(t, p.Enabled, n.Enabled, "%s enabled", n.Name)
		assert.Equalf(t, p.Description, n.Description, "%s description", n.Name)
		// A service can start or stop between the two reads; compare settled states.
		if isSettled(p.State) && isSettled(n.State) {
			assert.Equalf(t, p.State, n.State, "%s state", n.Name)
			assert.Equalf(t, p.Running, n.Running, "%s running", n.Name)
		}
	}
}

func isSettled(s State) bool {
	return s == ServiceRunning || s == ServiceStopped || s == ServicePaused
}

func TestResolveIndirectString(t *testing.T) {
	assert.Equal(t, "plain text", resolveIndirectString("plain text"))
	// A resource reference resolves to text, not to the reference itself.
	got := resolveIndirectString("@%SystemRoot%\\system32\\wuaueng.dll,-106")
	assert.NotEmpty(t, got)
	assert.NotContains(t, got, "wuaueng.dll")
	// One that does not resolve is returned as it is.
	assert.Equal(t, "@nonexistent.dll,-1", resolveIndirectString("@nonexistent.dll,-1"))
}

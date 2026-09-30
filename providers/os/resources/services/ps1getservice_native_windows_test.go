// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package services

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/powershell"
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
	// A second native read after the PowerShell one: a service whose state
	// differs between the two native reads changed while PowerShell ran.
	// Trigger-start services, such as sppsvc, do that even when they are not
	// manual.
	after, err := nativeWindowsServices()
	require.NoError(t, err)
	stateAfter := map[string]State{}
	for _, s := range after {
		stateAfter[s.Name] = s.State
	}
	raw, err := powershell.UnmarshalList[WindowsService](bytes.TrimSpace(out))
	require.NoError(t, err)
	manual := map[string]bool{}
	for _, r := range raw {
		manual[r.Name] = r.StartType == 3
	}

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
		// PowerShell's output reaches the provider through the console code
		// page (IBM437 on an English host), which turns characters outside
		// it, such as the typographic apostrophe U+2019 and the en dash
		// U+2013 in several descriptions, into their closest ASCII. The
		// native path returns what Windows stores; compare both folded to
		// ASCII.
		assert.Equalf(t, asciiFold(p.Description), asciiFold(n.Description), "%s description", n.Name)
		// A service can start or stop between the reads: demand-start
		// services such as TrustedInstaller and trigger-start services such
		// as sppsvc do. Compare settled states, only for services that are
		// not manual (demand-start) and whose state held across the reads.
		if isSettled(p.State) && isSettled(n.State) && !manual[n.Name] && stateAfter[n.Name] == n.State {
			assert.Equalf(t, p.State, n.State, "%s state", n.Name)
			assert.Equalf(t, p.Running, n.Running, "%s running", n.Name)
		}
	}
}

func isSettled(s State) bool {
	return s == ServiceRunning || s == ServiceStopped || s == ServicePaused
}

// asciiFold maps typographic punctuation to ASCII and drops any other
// character outside ASCII, which the console code page may render as "?".
func asciiFold(s string) string {
	s = strings.NewReplacer("\u2019", "'", "\u2018", "'", "\u201c", "\"", "\u201d", "\"", "\u2013", "-", "\u2014", "-").Replace(s)
	return strings.Map(func(r rune) rune {
		if r > 127 || r == '?' {
			return -1
		}
		return r
	}, s)
}

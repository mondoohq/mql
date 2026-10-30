// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package groups

import (
	"os/exec"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runPowerShell runs the PowerShell path's command on this machine.
func runPowerShell(t *testing.T, cmd string) []byte {
	t.Helper()
	fields := strings.Fields(cmd) // powershell.exe -NoProfile -EncodedCommand <base64>
	out, err := exec.Command(fields[0], fields[1:]...).Output()
	require.NoError(t, err)
	return out
}

// The native groups equal what the PowerShell path reports on the same host:
// names, SIDs, descriptions, and every group's members by SID and name.
func TestNativeGroupsMatchPowerShell(t *testing.T) {
	ps, err := ParseWindowsLocalGroups(strings.NewReader(string(runPowerShell(t, GetLocalGroupsCommand()))))
	require.NoError(t, err)
	native, err := nativeWindowsLocalGroups()
	require.NoError(t, err)

	byName := func(gs []WindowsLocalGroup) map[string]WindowsLocalGroup {
		m := map[string]WindowsLocalGroup{}
		for _, g := range gs {
			m[g.Name] = g
		}
		return m
	}
	want, got := byName(ps), byName(native)
	require.Equal(t, len(want), len(got))
	for name, w := range want {
		g, ok := got[name]
		require.True(t, ok, name)
		assert.Equal(t, w.SID.Value, g.SID.Value, name)
		assert.Equal(t, w.Description, g.Description, name)
		assert.Equal(t, w.MembersError, g.MembersError, name)
		assert.Equal(t, memberKeys(w.Members), memberKeys(g.Members), name)
	}
}

func memberKeys(ms []WindowsGroupMember) []string {
	res := make([]string, 0, len(ms))
	for _, m := range ms {
		res = append(res, m.Sid+" "+strings.ToLower(m.Name))
	}
	sort.Strings(res)
	return res
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"bytes"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runPowerShell runs a Get-WindowsOptionalFeature query the way the provider's
// PowerShell path does and parses it with the same parser.
func runPowerShell(t *testing.T, query string) []WindowsOptionalFeature {
	t.Helper()
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query).Output()
	if err != nil {
		t.Skipf("Get-WindowsOptionalFeature is not available here (it needs elevation): %v", err)
	}
	features, err := ParseWindowsOptionalFeatures(bytes.NewReader(out))
	require.NoError(t, err)
	return features
}

// The native list equals Get-WindowsOptionalFeature -Online: the same names,
// each with the same state.
func TestNativeOptionalFeaturesMatchPowerShell(t *testing.T) {
	native, err := NativeOptionalFeatures()
	if err != nil {
		t.Skipf("DISM is not available here (it needs elevation): %v", err)
	}
	ps := runPowerShell(t, QUERY_OPTIONAL_FEATURES)
	require.NotEmpty(t, ps)

	want := map[string]int64{}
	for _, f := range ps {
		want[f.Name] = f.State
	}
	got := map[string]int64{}
	for _, f := range native {
		got[f.Name] = f.State
		assert.Equal(t, f.State == 2, f.Enabled, "%s", f.Name)
	}
	assert.Equal(t, want, got)
}

// One feature by name, with its display name and description, equals the
// PowerShell path's targeted query; an unknown name and another spelling are
// not found, as with the PowerShell path's exact-name match.
func TestNativeOptionalFeatureMatchesPowerShell(t *testing.T) {
	const name = "SMB1Protocol"
	native, found, err := NativeOptionalFeature(name)
	if err != nil {
		t.Skipf("DISM is not available here (it needs elevation): %v", err)
	}
	require.True(t, found)
	ps := runPowerShell(t, OptionalFeatureQuery(name))
	require.Len(t, ps, 1)
	assert.Equal(t, ps[0].Name, native.Name)
	assert.Equal(t, ps[0].DisplayName, native.DisplayName)
	assert.Equal(t, ps[0].Description, native.Description)
	assert.Equal(t, ps[0].State, native.State)
	assert.Equal(t, ps[0].Enabled, native.Enabled)

	_, found, err = NativeOptionalFeature("No-Such-Feature-For-The-Test")
	require.NoError(t, err)
	assert.False(t, found)

	_, found, err = NativeOptionalFeature("smb1protocol")
	require.NoError(t, err)
	assert.False(t, found, "the name must match exactly, as on the PowerShell path")
}

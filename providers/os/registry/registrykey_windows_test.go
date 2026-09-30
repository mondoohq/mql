// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
)

func TestParseRegistryKeyPath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		wantKey     registry.Key
		wantPath    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "HKEY_LOCAL_MACHINE full prefix",
			path:     `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft`,
			wantKey:  registry.LOCAL_MACHINE,
			wantPath: `SOFTWARE\Microsoft`,
		},
		{
			name:     "HKLM short prefix",
			path:     `HKLM\SOFTWARE\Microsoft`,
			wantKey:  registry.LOCAL_MACHINE,
			wantPath: `SOFTWARE\Microsoft`,
		},
		{
			name:     "HKEY_CURRENT_USER full prefix",
			path:     `HKEY_CURRENT_USER\Software\Classes`,
			wantKey:  registry.CURRENT_USER,
			wantPath: `Software\Classes`,
		},
		{
			name:     "HKCU short prefix",
			path:     `HKCU\Software\Classes`,
			wantKey:  registry.CURRENT_USER,
			wantPath: `Software\Classes`,
		},
		{
			name:     "HKEY_USERS prefix",
			path:     `HKEY_USERS\.DEFAULT`,
			wantKey:  registry.USERS,
			wantPath: `.DEFAULT`,
		},
		{
			name:     "hive name in any case",
			path:     `hklm\SOFTWARE\Microsoft`,
			wantKey:  registry.LOCAL_MACHINE,
			wantPath: `SOFTWARE\Microsoft`,
		},
		{
			name:     "long hive name in any case",
			path:     `Hkey_Current_User\Software`,
			wantKey:  registry.CURRENT_USER,
			wantPath: `Software`,
		},
		{
			name:     "hive root",
			path:     `HKEY_USERS`,
			wantKey:  registry.USERS,
			wantPath: ``,
		},
		{
			name:        "a hive name must end at a separator",
			path:        `HKLMX\Software`,
			wantErr:     true,
			errContains: "invalid registry key hive",
		},
		{
			name:        "invalid hive returns error",
			path:        `HKEY_INVALID\Some\Path`,
			wantErr:     true,
			errContains: "invalid registry key hive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, path, err := parseRegistryKeyPath(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantKey, key)
			assert.Equal(t, tt.wantPath, path)
		})
	}
}

func TestGetNativeRegistryKeyItems_Integration(t *testing.T) {
	// This key exists on every Windows installation
	items, err := GetNativeRegistryKeyItems(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	require.NoError(t, err)
	require.NotEmpty(t, items, "CurrentVersion should have registry values")

	// Check that well-known values exist
	found := make(map[string]bool)
	for _, item := range items {
		found[item.Key] = true
	}
	assert.True(t, found["CurrentBuild"], "expected CurrentBuild value")
	assert.True(t, found["ProductName"], "expected ProductName value")
}

func TestGetNativeRegistryKeyChildren_Integration(t *testing.T) {
	// This key exists on every Windows installation and has children
	children, err := GetNativeRegistryKeyChildren(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft`)
	require.NoError(t, err)
	require.NotEmpty(t, children, "HKLM\\SOFTWARE\\Microsoft should have subkeys")

	// Check that at least "Windows NT" subkey exists
	found := false
	for _, child := range children {
		if child.Name == "Windows NT" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected 'Windows NT' subkey under HKLM\\SOFTWARE\\Microsoft")
}

func TestGetNativeRegistryKeyItems_NotFound(t *testing.T) {
	_, err := GetNativeRegistryKeyItems(`HKEY_LOCAL_MACHINE\SOFTWARE\NonExistentKey12345`)
	require.Error(t, err)
}

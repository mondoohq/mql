// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package registry

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
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

var procRegSetValueExW = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegSetValueExW")

// setRawValue stores a value of any kind, including the ones
// golang.org/x/sys/windows/registry has no setter for.
func setRawValue(t *testing.T, k registry.Key, name string, kind uint32, data []byte) {
	t.Helper()
	pname, err := windows.UTF16PtrFromString(name)
	require.NoError(t, err)
	var pdata *byte
	if len(data) > 0 {
		pdata = &data[0]
	}
	ret, _, _ := procRegSetValueExW.Call(uintptr(k), uintptr(unsafe.Pointer(pname)), 0, uintptr(kind), uintptr(unsafe.Pointer(pdata)), uintptr(len(data)))
	require.Zero(t, ret, "RegSetValueExW %s", name)
}

// TestRegistryValuesNativeMatchPowerShell writes one value of every kind to a
// scratch key, reads the key with the native reader and with the PowerShell
// collection script the remote path runs, and asserts every value decodes the
// same on both. A difference is a query that answers differently depending on
// how the host is reached (REG_EXPAND_SZ used to come back expanded over
// PowerShell only).
func TestRegistryValuesNativeMatchPowerShell(t *testing.T) {
	sub := fmt.Sprintf(`Software\mql-registry-test-%d`, os.Getpid())
	k, _, err := registry.CreateKey(registry.CURRENT_USER, sub, registry.ALL_ACCESS)
	require.NoError(t, err)
	t.Cleanup(func() {
		k.Close()
		_ = registry.DeleteKey(registry.CURRENT_USER, sub)
	})

	require.NoError(t, k.SetStringValue("Sz", "hello"))
	require.NoError(t, k.SetExpandStringValue("ExpandSz", `%SystemRoot%\system32\logfiles\firewall\domainfw.log`))
	require.NoError(t, k.SetDWordValue("Dword", 42))
	require.NoError(t, k.SetQWordValue("Qword", 5000000000))
	require.NoError(t, k.SetStringsValue("MultiSz", []string{"alpha", "beta"}))
	require.NoError(t, k.SetStringsValue("MultiSzEmpty", []string{}))
	require.NoError(t, k.SetBinaryValue("Binary", []byte{0xde, 0xad, 0xbe, 0xef}))
	be := make([]byte, 4)
	binary.BigEndian.PutUint32(be, 42)
	setRawValue(t, k, "DwordBigEndian", registry.DWORD_BIG_ENDIAN, be)
	setRawValue(t, k, "Link", registry.LINK, []byte{0x41, 0, 0x42, 0})
	setRawValue(t, k, "ResourceList", registry.RESOURCE_LIST, []byte{1, 0, 0, 0, 5})
	setRawValue(t, k, "FullResourceDescriptor", registry.FULL_RESOURCE_DESCRIPTOR, []byte{2, 3})

	path := `HKEY_CURRENT_USER\` + sub
	native, err := GetNativeRegistryKeyItems(path)
	require.NoError(t, err)

	script := filepath.Join(t.TempDir(), "values.ps1")
	require.NoError(t, os.WriteFile(script, []byte(GetRegistryKeyItemScript(path)), 0o600))
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script).Output()
	require.NoError(t, err)
	remote, err := ParsePowershellRegistryKeyItems(bytes.NewReader(out))
	require.NoError(t, err)

	byName := map[string]RegistryKeyItem{}
	for _, item := range remote {
		byName[item.Key] = item
	}
	require.Len(t, native, 11)
	for _, n := range native {
		p, ok := byName[n.Key]
		require.True(t, ok, "PowerShell did not report %s", n.Key)
		require.NoError(t, n.Value.Err, n.Key)
		require.NoError(t, p.Value.Err, n.Key)
		assert.Equal(t, n.Value.Kind, p.Value.Kind, "%s kind", n.Key)
		assert.Equal(t, n.Kind(), p.Kind(), "%s type", n.Key)
		assert.Equal(t, n.String(), p.String(), "%s value", n.Key)
		assert.Equal(t, n.GetRawValue(), p.GetRawValue(), "%s data", n.Key)
	}
	assert.Equal(t, `%SystemRoot%\system32\logfiles\firewall\domainfw.log`, byName["ExpandSz"].String())
	assert.Equal(t, int64(5000000000), byName["Qword"].GetRawValue())
	assert.Equal(t, int64(42), byName["DwordBigEndian"].GetRawValue())
	assert.Equal(t, "AB", byName["Link"].String())
}

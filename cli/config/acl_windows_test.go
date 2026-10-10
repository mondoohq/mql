// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package config

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

const (
	sidEveryone           = "S-1-1-0"
	sidAuthenticatedUsers = "S-1-5-11"
	sidBuiltinUsers       = "S-1-5-32-545"
	sidSystem             = "S-1-5-18"
	sidAdministrators     = "S-1-5-32-544"
)

// fakeProgramData points programDataDir at a temporary directory for the test
// and makes sure the files the test restricts can be removed afterwards.
func fakeProgramData(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	prev := programDataDir
	programDataDir = func() string { return root }
	t.Cleanup(func() {
		programDataDir = prev
		// The test account may not be able to delete a file only SYSTEM and
		// Administrators can access. Give it back an inherited access list.
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				resetAccess(path)
			}
			return nil
		})
	})
	return root
}

func resetAccess(path string) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return
	}
	sd, err := windows.SecurityDescriptorFromString("D:(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return
	}
	dacl, _, _ := sd.DACL()
	_ = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// aceSIDs reads the access list of path back and returns whether it is
// protected from inheritance and the SID of every allow entry.
func aceSIDs(t *testing.T, path string) (protected bool, sids []string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	control, _, err := sd.Control()
	require.NoError(t, err)
	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NotNil(t, dacl, "a nil access list grants everyone access")

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(dacl, i, &ace))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		sids = append(sids, sid.String())
	}
	return control&windows.SE_DACL_PROTECTED != 0, sids
}

func assertSystemOnly(t *testing.T, path string) {
	t.Helper()
	protected, sids := aceSIDs(t, path)
	assert.True(t, protected, "access list must not inherit from the folder")
	assert.Contains(t, sids, sidSystem)
	assert.Contains(t, sids, sidAdministrators)
	for _, sid := range sids {
		assert.NotEqual(t, sidEveryone, sid)
		assert.NotEqual(t, sidAuthenticatedUsers, sid)
		assert.NotEqual(t, sidBuiltinUsers, sid)
	}
}

func TestIsUnderProgramData(t *testing.T) {
	root := fakeProgramData(t)
	assert.True(t, isUnderProgramData(filepath.Join(root, "Mondoo", "mondoo.yml")))
	assert.True(t, isUnderProgramData(filepath.Join(root, "MONDOO", "Mondoo.yml")))
	assert.False(t, isUnderProgramData(root))
	assert.False(t, isUnderProgramData(filepath.Join(root, "mondoo.yml")), "a file directly in ProgramData")
	assert.False(t, isUnderProgramData(filepath.Join(filepath.Dir(root), "elsewhere", "mondoo.yml")))
	assert.False(t, isUnderProgramData(filepath.Join(root, "..", "Mondoo", "mondoo.yml")))
}

func TestWritePrivateFileRestrictsAccessUnderProgramData(t *testing.T) {
	root := fakeProgramData(t)
	dir := filepath.Join(root, "Mondoo")
	require.NoError(t, os.MkdirAll(dir, 0o755))

	t.Run("new file", func(t *testing.T) {
		path := filepath.Join(dir, "mondoo.yml")
		require.NoError(t, WritePrivateFile(path, []byte("private_key: test\n")))
		assertSystemOnly(t, path)
	})

	// A file written by an older version carries the inherited access list. The
	// next write repairs it.
	t.Run("existing file is repaired", func(t *testing.T) {
		path := filepath.Join(dir, "inventory.yml")
		require.NoError(t, os.WriteFile(path, []byte("old\n"), 0o644))
		_, sids := aceSIDs(t, path)
		require.NotEmpty(t, sids)

		require.NoError(t, WritePrivateFile(path, []byte("new\n")))
		assertSystemOnly(t, path)
	})
}

func TestAppendConfigKeyRestrictsAccessUnderProgramData(t *testing.T) {
	root := fakeProgramData(t)
	dir := filepath.Join(root, "Mondoo")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, "mondoo.yml")
	require.NoError(t, os.WriteFile(path, []byte("api_endpoint: https://example.com\n"), 0o644))

	require.NoError(t, appendConfigKey(path, "updates_url", "https://example.com"))
	assertSystemOnly(t, path)
}

func TestWritePrivateFileKeepsInheritedAccessOutsideProgramData(t *testing.T) {
	fakeProgramData(t)
	path := filepath.Join(t.TempDir(), "mondoo.yml")
	require.NoError(t, WritePrivateFile(path, []byte("private_key: test\n")))
	protected, _ := aceSIDs(t, path)
	assert.False(t, protected, "a config outside ProgramData keeps its inherited access list")
}

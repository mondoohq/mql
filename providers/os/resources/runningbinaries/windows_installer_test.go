// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

func TestWindowsInstallerOwnersScriptFitsCommandLine(t *testing.T) {
	assert.True(t, powershell.FitsCommandLine(windowsInstallerOwnersScript))
}

func TestParseWindowsInstallerOwners(t *testing.T) {
	data := []byte(`[
  {"Path": "C:\\Program Files\\Mondoo\\cnspec.exe", "Product": "Mondoo"},
  {"Path": "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe", "Product": "VMware Tools"},
  {"Path": "C:\\PROGRAM FILES\\VMware\\VMware Tools\\vmtoolsd.exe", "Product": "VMware Tools Plugin"},
  {"Path": "C:\\Tools\\orphan.exe", "Product": ""}
]`)
	owners, err := parseWindowsInstallerOwners(data)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		`c:\program files\mondoo\cnspec.exe`: "Mondoo",
		// a component two products share stays with the first
		`c:\program files\vmware\vmware tools\vmtoolsd.exe`: "VMware Tools",
	}, owners)

	// looked up the way Windows compares paths
	assert.Equal(t, "Mondoo", owners[WindowsPathKey(`C:\PROGRAM FILES\Mondoo\cnspec.exe`)])

	// a lone object, as ConvertTo-Json may write it, and no output at all
	owners, err = parseWindowsInstallerOwners([]byte(`{"Path": "D:\\app.exe", "Product": "App"}`))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{`d:\app.exe`: "App"}, owners)
	owners, err = parseWindowsInstallerOwners([]byte("[]"))
	require.NoError(t, err)
	assert.Empty(t, owners)

	_, err = parseWindowsInstallerOwners([]byte("not json"))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA, llx.KindOf(err))
}

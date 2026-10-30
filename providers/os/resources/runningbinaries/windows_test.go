// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWindowsProcessBinaries(t *testing.T) {
	data := []byte(`[
  {
    "Path": "C:\\Windows\\System32\\svchost.exe",
    "Ids": [1204, 988],
    "ProductName": "Microsoft® Windows® Operating System",
    "ProductVersion": "10.0.20348.1",
    "FileVersion": "10.0.20348.1 (WinBuild.160101.0800)",
    "CompanyName": "Microsoft Corporation",
    "FileDescription": "Host Process for Windows Services",
    "SystemRoot": "C:\\WINDOWS"
  },
  {
    "Path": "C:\\Tools\\agent.exe",
    "Ids": [4410],
    "ProductName": null,
    "ProductVersion": null,
    "FileVersion": null,
    "CompanyName": null,
    "SystemRoot": "C:\\WINDOWS"
  }
]`)
	bins, err := parseWindowsProcessBinaries(data)
	require.NoError(t, err)
	require.Len(t, bins, 2)

	assert.Equal(t, Binary{
		Path:   `C:\Windows\System32\svchost.exe`,
		Pids:   []int64{988, 1204},
		System: true,
		VersionInfo: &PEVersionInfo{
			ProductName:     "Microsoft® Windows® Operating System",
			ProductVersion:  "10.0.20348.1",
			FileVersion:     "10.0.20348.1 (WinBuild.160101.0800)",
			CompanyName:     "Microsoft Corporation",
			FileDescription: "Host Process for Windows Services",
		},
	}, bins[0])

	// no version resource at all reads as none, not as an empty one
	assert.Equal(t, Binary{Path: `C:\Tools\agent.exe`, Pids: []int64{4410}}, bins[1])
}

func TestParseWindowsProcessBinariesSingleObject(t *testing.T) {
	// ConvertTo-Json writes a lone object, not a one-element array
	data := []byte(`{"Path": "D:\\nginx\\nginx.exe", "Ids": 512, "SystemRoot": "C:\\Windows"}`)
	bins, err := parseWindowsProcessBinaries(data)
	require.NoError(t, err)
	require.Len(t, bins, 1)
	assert.Equal(t, `D:\nginx\nginx.exe`, bins[0].Path)
	assert.Equal(t, []int64{512}, bins[0].Pids)
	assert.False(t, bins[0].System)
}

func TestParseWindowsProcessBinariesEmpty(t *testing.T) {
	bins, err := parseWindowsProcessBinaries([]byte("\r\n"))
	require.NoError(t, err)
	assert.Empty(t, bins)
}

func TestWindowsPathWithin(t *testing.T) {
	assert.True(t, windowsPathWithin(`c:\windows\system32\a.exe`, `C:\Windows`))
	assert.True(t, windowsPathWithin(`C:\Windows\a.exe`, `C:\Windows\`))
	assert.True(t, windowsPathWithin(`\\?\C:\Windows\a.exe`, `C:/Windows`))
	// a sibling whose name starts the same is not inside
	assert.False(t, windowsPathWithin(`C:\WindowsApps\a.exe`, `C:\Windows`))
	assert.False(t, windowsPathWithin(`C:\Windows\a.exe`, ``))
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	win "go.mondoo.com/mql/providers/os/detector/windows"
)

func TestFamilyParents(t *testing.T) {
	test := []struct {
		Platform string
		Expected []string
	}{
		{
			Platform: "redhat",
			Expected: []string{"os", "unix", "linux", "redhat"},
		},
		{
			Platform: "centos",
			Expected: []string{"os", "unix", "linux", "redhat"},
		},
		{
			Platform: "debian",
			Expected: []string{"os", "unix", "linux", "debian"},
		},
		{
			Platform: "ubuntu",
			Expected: []string{"os", "unix", "linux", "debian"},
		},
	}

	for i := range test {
		assert.Equal(t, test[i].Expected, Family(test[i].Platform), test[i].Platform)
	}
}

func TestIsFamily(t *testing.T) {
	test := []struct {
		Val      bool
		Expected bool
	}{
		{
			Val:      IsFamily("redhat", inventory.FAMILY_LINUX),
			Expected: true,
		},
		{
			Val:      IsFamily("redhat", inventory.FAMILY_UNIX),
			Expected: true,
		},
		{
			Val:      IsFamily("redhat", "redhat"),
			Expected: true,
		},
		{
			Val:      IsFamily("centos", inventory.FAMILY_LINUX),
			Expected: true,
		},
		{
			Val:      IsFamily("centos", "redhat"),
			Expected: true,
		},
	}

	for i := range test {
		assert.Equal(t, test[i].Expected, test[i].Val, i)
	}
}

func TestFamilies(t *testing.T) {
	di := &inventory.Platform{}
	di.Family = []string{"unix", "bsd", "darwin"}

	assert.Equal(t, true, di.IsFamily("unix"), "unix should be a family")
	assert.Equal(t, true, di.IsFamily("bsd"), "bsd should be a family")
	assert.Equal(t, true, di.IsFamily("darwin"), "darwin should be a family")
}

func TestWindowsPlatform(t *testing.T) {
	tests := []struct {
		name     string
		current  win.WindowsCurrentVersion
		expected *inventory.Platform
	}{
		{
			name: "windows 10",
			current: win.WindowsCurrentVersion{
				CurrentBuild:     "19044",
				EditionID:        "Professional",
				ReleaseId:        "2009",
				InstallationType: "Client",
				ProductName:      "Windows 10 Pro",
				DisplayVersion:   "21H2",
				UBR:              2728,
				Architecture:     "x64",
				ProductType:      "WinNT",
			},
			expected: &inventory.Platform{
				Name:    "windows",
				Title:   "Windows 10 Pro",
				Version: "19044",
				Build:   "2728",
				Arch:    "x64",
				Labels: map[string]string{
					"windows.mondoo.com/product-type":    "1",
					"windows.mondoo.com/display-version": "21H2",
					"windows.mondoo.com/edition-id":      "Professional",
				},
			},
		},
		{
			name: "windows 11",
			current: win.WindowsCurrentVersion{
				CurrentBuild:     "22631",
				EditionID:        "Professional",
				ReleaseId:        "23H2",
				InstallationType: "Client",
				ProductName:      "Windows 10 Pro",
				DisplayVersion:   "23H2",
				UBR:              2506,
				Architecture:     "x64",
				ProductType:      "WinNT",
			},
			expected: &inventory.Platform{
				Name:    "windows",
				Title:   "Windows 11 Pro",
				Version: "22631",
				Build:   "2506",
				Arch:    "x64",
				Labels: map[string]string{
					"windows.mondoo.com/product-type":    "1",
					"windows.mondoo.com/display-version": "23H2",
					"windows.mondoo.com/edition-id":      "Professional",
				},
			},
		},
		{
			name: "windows server",
			current: win.WindowsCurrentVersion{
				CurrentBuild:     "20348",
				EditionID:        "ServerStandard",
				ReleaseId:        "21H2",
				InstallationType: "Server",
				ProductName:      "Windows Server 2022 Standard",
				DisplayVersion:   "21H2",
				UBR:              1972,
				Architecture:     "x64",
				ProductType:      "ServerNT",
			},
			expected: &inventory.Platform{
				Name:    "windows",
				Title:   "Windows Server 2022 Standard",
				Version: "20348",
				Build:   "1972",
				Arch:    "x64",
				Labels: map[string]string{
					"windows.mondoo.com/product-type":    "3",
					"windows.mondoo.com/display-version": "21H2",
					"windows.mondoo.com/edition-id":      "ServerStandard",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := &inventory.Platform{}
			platformFromWinCurrentVersion(pf, &tt.current)

			assert.Equal(t, tt.expected, pf)
		})
	}
}

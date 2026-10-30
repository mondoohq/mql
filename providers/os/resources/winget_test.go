// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

const (
	testWingetX64    = "Microsoft.DesktopAppInstaller_1.29.380.0_x64__8wekyb3d8bbwe"
	testVclibsX64    = "Microsoft.VCLibs.140.00_14.0.33519.0_x64__8wekyb3d8bbwe"
	testUwpDesktop   = "Microsoft.VCLibs.140.00.UWPDesktop_14.0.33728.0_x64__8wekyb3d8bbwe"
	testAppRuntime18 = "Microsoft.WindowsAppRuntime.1.8_8000.616.304.0_x64__8wekyb3d8bbwe"
)

func wingetFixtureState(t *testing.T, packages ...string) *windows.WingetState {
	t.Helper()
	manifest, err := os.ReadFile("windows/testdata/winget/AppxManifest_1.29.380.0_x64.xml")
	require.NoError(t, err)
	return &windows.WingetState{
		MachineArch: "AMD64",
		Packages:    packages,
		Candidates: []windows.WingetCandidate{{
			FullName: testWingetX64,
			Root:     `C:\Program Files\WindowsApps\` + testWingetX64,
			HasExe:   true,
			Manifest: windows.PSString(manifest),
		}},
	}
}

func TestComputeWinget_SingleDirectoryUsable(t *testing.T) {
	r := computeWinget(wingetFixtureState(t, testWingetX64, testVclibsX64, testUwpDesktop, testAppRuntime18))
	assert.True(t, r.installed)
	require.NotNil(t, r.version)
	assert.Equal(t, "1.29.380.0", *r.version)
	require.NotNil(t, r.architecture)
	assert.Equal(t, "x64", *r.architecture)
	require.NotNil(t, r.path)
	assert.Equal(t, `C:\Program Files\WindowsApps\`+testWingetX64+`\winget.exe`, *r.path)
	assert.Equal(t, []string{}, r.missingDependencies)
	require.NotNil(t, r.systemUsable)
	assert.True(t, *r.systemUsable)
	require.NotNil(t, r.enabledByPolicy)
	assert.True(t, *r.enabledByPolicy)
}

func TestComputeWinget_MissingDependency(t *testing.T) {
	r := computeWinget(wingetFixtureState(t, testWingetX64, testVclibsX64, testUwpDesktop))
	assert.True(t, r.installed)
	assert.Equal(t, []string{"Microsoft.WindowsAppRuntime.1.8 >= 8000.616.304.0"}, r.missingDependencies)
	require.NotNil(t, r.systemUsable)
	assert.False(t, *r.systemUsable)
}

func TestComputeWinget_DisabledByPolicy(t *testing.T) {
	s := wingetFixtureState(t, testWingetX64, testVclibsX64, testUwpDesktop, testAppRuntime18)
	zero := int64(0)
	s.Policy = &windows.WingetPolicy{EnableWindowsPackageManagerCommandLineInterfaces: &zero}
	r := computeWinget(s)
	assert.True(t, r.installed)
	require.NotNil(t, r.systemUsable)
	assert.False(t, *r.systemUsable)
	require.NotNil(t, r.enabledByPolicy)
	assert.False(t, *r.enabledByPolicy)
}

// An unreadable manifest leaves the dependencies unknown, so the answer is
// null rather than a guess.
func TestComputeWinget_ManifestUnreadable(t *testing.T) {
	s := wingetFixtureState(t, testWingetX64)
	s.Candidates[0].Manifest = ""
	r := computeWinget(s)
	assert.True(t, r.installed)
	assert.Nil(t, r.missingDependencies)
	assert.Nil(t, r.systemUsable)
}

// A disabling policy settles systemUsable even when the dependencies are
// unknown.
func TestComputeWinget_DisabledByPolicyManifestUnreadable(t *testing.T) {
	s := wingetFixtureState(t, testWingetX64)
	s.Candidates[0].Manifest = ""
	zero := int64(0)
	s.Policy = &windows.WingetPolicy{EnableAppInstaller: &zero}
	r := computeWinget(s)
	assert.Nil(t, r.missingDependencies)
	require.NotNil(t, r.systemUsable)
	assert.False(t, *r.systemUsable)
}

// version reports winget.exe's product version, which can be ahead of the
// package version (App Installer 1.29.379.0_arm64 ships winget 1.29.380).
func TestComputeWinget_VersionFromExe(t *testing.T) {
	s := wingetFixtureState(t, testWingetX64)
	s.Candidates[0].ExeVersion = "1.29.381.0"
	r := computeWinget(s)
	require.NotNil(t, r.version)
	assert.Equal(t, "1.29.381.0", *r.version)
	require.NotNil(t, r.packageFullName)
	assert.Equal(t, testWingetX64, *r.packageFullName)
}

func TestComputeWinget_VersionFallsBackToPackage(t *testing.T) {
	s := wingetFixtureState(t, testWingetX64)
	s.Candidates[0].ExeVersion = "  "
	r := computeWinget(s)
	require.NotNil(t, r.version)
	assert.Equal(t, "1.29.380.0", *r.version)
}

func TestComputeWinget_NotInstalled(t *testing.T) {
	r := computeWinget(&windows.WingetState{MachineArch: "AMD64"})
	assert.False(t, r.installed)
	assert.Nil(t, r.version)
	assert.Nil(t, r.path)
	assert.Nil(t, r.missingDependencies)
	require.NotNil(t, r.systemUsable)
	assert.False(t, *r.systemUsable)
	// the default sources are still reported: they are what winget would use
	assert.Len(t, r.sources, 3)
}

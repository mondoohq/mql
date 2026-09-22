// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// TestCollapsePackages_IdenticalRowsCollapse is the ticket's core case: the
// .NET runtime's two Add/Remove-Programs entries (the bundle's own entry and
// the MSI's hidden SystemComponent=1 entry) become identical in every field
// once normalizeDotNetPackedVersion has rewritten both DisplayVersions to
// the release their shared DisplayName carries -- and once they are
// identical, they must collapse to one row.
func TestCollapsePackages_IdenticalRowsCollapse(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "arm64", Family: []string{"windows"}}
	bundleEntry := *createPackage("Microsoft .NET Runtime - 8.0.30 (arm64)", "8.0.30.36323", "windows/app", "x86", "Microsoft Corporation",
		`C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.30`, platform)
	msiEntry := *createPackage("Microsoft .NET Runtime - 8.0.30 (arm64)", "64.120.56881", "windows/app", "arm64", "Microsoft Corporation",
		`C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.30`, platform)
	bundleEntry.InstallScope = installScopeMachine
	msiEntry.InstallScope = installScopeMachine

	// createPackage already applies normalizeDotNetPackedVersion/
	// normalizeDotNetInstallerArch (format == "windows/app"), so both rows
	// should already agree on version, arch and purl before collapsing --
	// pin that precondition, since collapsePackages does nothing if they
	// don't.
	require.Equal(t, bundleEntry.Version, msiEntry.Version, "precondition: normalization must have already converged both entries")
	require.Equal(t, bundleEntry.Arch, msiEntry.Arch, "precondition: normalization must have already converged both entries")
	require.Equal(t, bundleEntry.PUrl, msiEntry.PUrl, "precondition: normalization must have already converged both entries")

	got := collapsePackages([]Package{bundleEntry, msiEntry})
	require.Len(t, got, 1, "two rows identical in every field must collapse to one")
	assert.Equal(t, "8.0.30", got[0].Version)
	assert.Equal(t, "arm64", got[0].Arch)
}

// TestCollapsePackages_DifferentInstallUserNeverCollapses is the critical
// correctness constraint the ticket calls out by name: #10964 made mql
// report a package once per user profile it is installed for, and two
// different users each having their own install of the same app share every
// field EXCEPT installUser (and typically installScope="user" for both).
// Collapsing across installUser would destroy that per-user attribution.
func TestCollapsePackages_DifferentInstallUserNeverCollapses(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "x64", Family: []string{"windows"}}
	base := *createPackage("Visual Studio Code", "1.95.0", "windows/app", "x64", "Microsoft Corporation", "", platform)

	alice := base
	alice.InstallScope = installScopeUser
	alice.InstallUser = "S-1-5-21-1111111111-2222222222-3333333333-1001"

	bob := base
	bob.InstallScope = installScopeUser
	bob.InstallUser = "S-1-5-21-1111111111-2222222222-3333333333-1002"

	got := collapsePackages([]Package{alice, bob})
	require.Len(t, got, 2, "two different users' own installs of the same app must both be reported")
	users := map[string]bool{got[0].InstallUser: true, got[1].InstallUser: true}
	assert.True(t, users[alice.InstallUser])
	assert.True(t, users[bob.InstallUser])
}

// TestCollapsePackages_DifferentInstallScopeNeverCollapses guards the other
// half of the same constraint: a machine-wide install and a per-user install
// that otherwise agree on every field are two distinct installs, not one row
// reported twice.
func TestCollapsePackages_DifferentInstallScopeNeverCollapses(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "x64", Family: []string{"windows"}}
	base := *createPackage("Visual Studio Code", "1.95.0", "windows/app", "x64", "Microsoft Corporation", "", platform)

	machineWide := base
	machineWide.InstallScope = installScopeMachine

	perUser := base
	perUser.InstallScope = installScopeUser
	perUser.InstallUser = "S-1-5-21-1111111111-2222222222-3333333333-1001"

	got := collapsePackages([]Package{machineWide, perUser})
	assert.Len(t, got, 2, "a machine install and a per-user install must not collapse")
}

// TestCollapsePackages_DifferentVersionNeverCollapses pins the base case:
// two genuinely different versions of the same app are not the same package.
func TestCollapsePackages_DifferentVersionNeverCollapses(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "x64", Family: []string{"windows"}}
	older := *createPackage("Some App", "1.0.0", "windows/app", "x64", "Vendor", "", platform)
	newer := *createPackage("Some App", "2.0.0", "windows/app", "x64", "Vendor", "", platform)

	got := collapsePackages([]Package{older, newer})
	assert.Len(t, got, 2)
}

// TestCollapsePackages_PreservesOrderAndOtherPackages pins that collapsing is
// scoped to exact duplicates: unrelated packages (different format, e.g. a
// hotfix or appx entry) pass through untouched, and first-appearance order is
// preserved, matching mergeDedupedRegistryPackages' own convention.
func TestCollapsePackages_PreservesOrderAndOtherPackages(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "arm64", Family: []string{"windows"}}
	dotnetBundle := *createPackage("Microsoft .NET Runtime - 8.0.30 (arm64)", "8.0.30.36323", "windows/app", "x86", "Microsoft Corporation", "", platform)
	dotnetBundle.InstallScope = installScopeMachine
	dotnetMsi := *createPackage("Microsoft .NET Runtime - 8.0.30 (arm64)", "64.120.56881", "windows/app", "arm64", "Microsoft Corporation", "", platform)
	dotnetMsi.InstallScope = installScopeMachine
	hotfix := Package{Name: "KB5031354", Format: "windows/hotfix", InstallScope: installScopeMachine}
	appx := Package{Name: "Microsoft.WindowsCalculator", Version: "1.0.0.0", Format: "windows/appx", InstallScope: installScopeMachine}

	got := collapsePackages([]Package{dotnetBundle, hotfix, dotnetMsi, appx})
	require.Len(t, got, 3, "the two dotnet entries collapse to one; hotfix and appx are untouched")
	assert.Equal(t, "8.0.30", got[0].Version, "first appearance order is preserved")
	assert.Equal(t, "KB5031354", got[1].Name)
	assert.Equal(t, "Microsoft.WindowsCalculator", got[2].Name)
}

// TestApplyOmahaVersionsThenCollapse_ChromeDuplicateResolvesToOneRow ties
// Part A and Part B together against the exact scenario in
// mondoohq/mql#10730: a host carries two Google Chrome ARP entries, one at
// the real browser version and one frozen at the raw MSI ProductVersion left
// behind because the post-install DisplayVersion rewrite never ran. Once
// Google Update's own "pv" is applied to both (applyOmahaVersions), they
// become identical and collapse (collapsePackages) to the single row a
// customer actually installed -- the order these two run in matters, and
// this is what pins it.
func TestApplyOmahaVersionsThenCollapse_ChromeDuplicateResolvesToOneRow(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "arm64", Family: []string{"windows"}}
	realEntry := *createPackage("Google Chrome", "153.0.8010.53", "windows/app", "arm64", "Google LLC", `C:\Program Files\Google\Chrome\Application`, platform)
	realEntry.InstallScope = installScopeMachine
	staleEntry := *createPackage("Google Chrome", "69.218.16502", "windows/app", "arm64", "Google LLC", `C:\Program Files\Google\Chrome\Application`, platform)
	staleEntry.InstallScope = installScopeMachine

	pkgs := []Package{realEntry, staleEntry}
	applyOmahaVersions(pkgs, map[string]string{"google chrome": "153.0.8010.53"}, platform)

	got := collapsePackages(pkgs)
	require.Len(t, got, 1, "one browser install must report as one package, not two")
	assert.Equal(t, "153.0.8010.53", got[0].Version)
}

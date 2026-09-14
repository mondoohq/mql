// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package selfupdate

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
)

// TestUpdateRegisteredVersion exercises the real registry against a real MSI
// install. It is skipped when there is no Mondoo package on the machine, which
// is every developer box and every CI runner; it earns its keep on a Windows
// host with the MSI installed.
func TestUpdateRegisteredVersion(t *testing.T) {
	productCode, err := installedProductCode()
	require.NoError(t, err)
	if productCode == "" {
		t.Skip("no MSI install on this machine")
	}

	path := uninstallKey + `\` + productCode
	before, err := registeredDisplayVersion(path)
	require.NoError(t, err, "the Add/Remove entry should be readable")
	t.Logf("DisplayVersion before: %q", before)

	// Restore whatever was there, so a test run does not leave the machine
	// reporting a version invented here.
	t.Cleanup(func() {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE|registry.WOW64_64KEY)
		if err != nil {
			t.Logf("could not restore DisplayVersion: %v", err)
			return
		}
		defer k.Close()
		if err := k.SetStringValue(displayVersionValue, before); err != nil {
			t.Logf("could not restore DisplayVersion: %v", err)
		}
	})

	const want = "99.99.99-test.1"
	require.NoError(t, updateRegisteredVersion(want))

	got, err := registeredDisplayVersion(path)
	require.NoError(t, err)
	require.Equal(t, want, got, "Windows should now report the version we wrote")
	t.Logf("DisplayVersion after:  %q", got)

	// Second call with the same value must be a no-op rather than a failure:
	// this runs on every update check, so the common case is "already agrees".
	require.NoError(t, updateRegisteredVersion(want))

	// An empty version is refused rather than blanking the entry.
	require.Error(t, updateRegisteredVersion(""))
	still, err := registeredDisplayVersion(path)
	require.NoError(t, err)
	require.Equal(t, want, still, "a refused write must not have changed anything")
}

// TestProductCodeFromUpgradeCodes exercises the fallback that finds the
// installed package when the installer recorded no ProductCode. Like the test
// above it needs a real MSI install, and skips without one.
//
// This is the path every package installed before the pointer key existed
// takes, so it is the one that decides whether those installs ever report the
// version they are actually running.
func TestProductCodeFromUpgradeCodes(t *testing.T) {
	productCode, err := productCodeFromUpgradeCodes()
	require.NoError(t, err)
	if productCode == "" {
		t.Skip("no Mondoo MSI install on this machine")
	}
	t.Logf("resolved ProductCode from UpgradeCode: %s", productCode)

	require.True(t, isMondooUninstallEntry(productCode),
		"the resolved product should have a Mondoo Add/Remove entry")

	// When the installer did record a ProductCode, the two routes have to
	// agree. Disagreement would mean the fallback can write to the wrong
	// package on machines that have both.
	if recorded, err := recordedProductCode(); err == nil && recorded != "" {
		require.Equal(t, recorded, productCode,
			"the UpgradeCode lookup should resolve the same package the installer recorded")
	}
}

// TestRelatedProductCodeUnknownUpgradeCode pins the contract that an
// UpgradeCode nothing is installed under is an ordinary answer and not an
// error. Every SKU the machine does not have takes this path on every update
// check, so treating it as a fault would make the common case noisy.
func TestRelatedProductCodeUnknownUpgradeCode(t *testing.T) {
	// A syntactically valid GUID that no product registers.
	productCode, err := relatedProductCode("{0F7E9A21-4C3B-4D5E-8A6F-1B2C3D4E5F60}")
	require.NoError(t, err)
	require.Empty(t, productCode)
}

// TestRelatedProductCodeRejectsMalformed confirms a malformed UpgradeCode is
// reported rather than silently treated as "nothing installed", which would
// hide a typo in the upgradeCodes list.
func TestRelatedProductCodeRejectsMalformed(t *testing.T) {
	_, err := relatedProductCode("not-a-guid")
	require.Error(t, err)
}

// TestUpgradeCodesAreWellFormed guards the hand-maintained list against a typo
// that would silently disable the fallback: a malformed entry returns an error
// and is skipped, so the list would degrade without anything failing.
func TestUpgradeCodesAreWellFormed(t *testing.T) {
	// Registry-format GUID: {8-4-4-4-12} upper-case hex. Checking the shape
	// rather than only the length catches a transposed dash, which would be
	// the right number of characters and still resolve nothing.
	guid := regexp.MustCompile(`^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$`)

	require.NotEmpty(t, upgradeCodes)
	seen := map[string]bool{}
	for _, code := range upgradeCodes {
		require.Len(t, code, productCodeGUIDLen-1, "%s should be a registry-format GUID", code)
		require.Regexp(t, guid, code, "%s should be a registry-format GUID", code)
		require.False(t, seen[code], "%s is listed twice", code)
		seen[code] = true
	}
}

// TestMondooDisplayNames pins the DisplayName set against the installer's WiX
// ProductName values. The match is exact, so a value drifting here silently
// disables the fallback for that SKU.
func TestMondooDisplayNames(t *testing.T) {
	require.True(t, mondooDisplayNames["Mondoo"])
	require.True(t, mondooDisplayNames["Mondoo Enterprise"])

	// A prefix test would accept these; an exact match must not.
	require.False(t, mondooDisplayNames["Mondoo "])
	require.False(t, mondooDisplayNames["MondooBackupTool"])
	require.False(t, mondooDisplayNames["mondoo"])
}

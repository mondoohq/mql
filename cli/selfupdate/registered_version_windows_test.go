// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package selfupdate

import (
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

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package services

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
)

// TestNativeServicesMatchPowerShell compares the Service Control Manager
// listing with Get-Service on the machine running the test. Every service
// Get-Service reports must be in the native list with the same description
// and start type, and, allowing for services that change state between the
// two reads, the same state.
func TestNativeServicesMatchPowerShell(t *testing.T) {
	mgr := &WindowsServiceManager{conn: local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})}

	native, err := listNativeWindowsServices()
	require.NoError(t, err)
	ps, err := mgr.listPowerShell()
	require.NoError(t, err)
	require.NotEmpty(t, ps, "Get-Service returned no services")

	nativeByName := servicesByName(native)
	psByName := servicesByName(ps)

	var missing []string
	stateMismatch := map[string]bool{}
	for name, want := range psByName {
		got, ok := nativeByName[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		require.Equal(t, want.Description, got.Description, "description of %s", name)
		require.Equal(t, want.Enabled, got.Enabled, "enabled of %s", name)
		require.Equal(t, want.Installed, got.Installed, "installed of %s", name)
		require.Equal(t, want.Type, got.Type, "type of %s", name)
		if !sameState(want, got) {
			stateMismatch[name] = true
		}
	}
	sort.Strings(missing)
	require.Empty(t, missing, "services Get-Service lists but the service control manager listing does not")

	var extra []string
	for name := range nativeByName {
		if _, ok := psByName[name]; !ok {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	t.Logf("native: %d services, Get-Service: %d services, only native: %v", len(native), len(ps), extra)

	// A service can start or stop between the two reads. Read both again and
	// only fail on a service whose state still differs.
	for attempt := 0; attempt < 3 && len(stateMismatch) > 0; attempt++ {
		time.Sleep(2 * time.Second)
		native, err = listNativeWindowsServices()
		require.NoError(t, err)
		ps, err = mgr.listPowerShell()
		require.NoError(t, err)
		nativeByName, psByName = servicesByName(native), servicesByName(ps)
		for name := range stateMismatch {
			want, okPs := psByName[name]
			got, okNative := nativeByName[name]
			if !okPs || !okNative || sameState(want, got) {
				delete(stateMismatch, name)
			}
		}
	}
	for name := range stateMismatch {
		t.Errorf("state of %s: Get-Service %s (running %v), native %s (running %v)", name,
			psByName[name].State, psByName[name].Running, nativeByName[name].State, nativeByName[name].Running)
	}
}

// TestNativeServicesUsedForLocalConnection checks that List on a local
// connection returns the Service Control Manager listing rather than falling
// back to PowerShell.
func TestNativeServicesUsedForLocalConnection(t *testing.T) {
	t.Setenv(windowsNativeEnvVar, "on")
	mgr := &WindowsServiceManager{conn: local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})}
	listed, err := mgr.List()
	require.NoError(t, err)
	native, err := listNativeWindowsServices()
	require.NoError(t, err)
	require.Len(t, listed, len(native))
}

// sameState compares two readings of a service's state.
func sameState(ps, native *Service) bool {
	return ps.State == native.State && ps.Running == native.Running
}

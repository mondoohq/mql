// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestGetWindowsHotpatch_Integration(t *testing.T) {
	conn := &mockLocalConnection{}

	// Get the current system's build info to construct a realistic platform
	ver, err := GetWindowsOSBuild(conn)
	require.NoError(t, err)

	pf := &inventory.Platform{
		Name:    "windows",
		Version: ver.CurrentBuild,
		Arch:    runtime.GOARCH,
		Labels: map[string]string{
			"windows.mondoo.com/product-type": "1",
		},
	}
	if ver.ProductType == "ServerNT" {
		pf.Labels["windows.mondoo.com/product-type"] = "3"
	} else if ver.ProductType == "LanmanNT" {
		pf.Labels["windows.mondoo.com/product-type"] = "2"
	}

	result, err := GetWindowsHotpatch(conn, pf)
	require.NoError(t, err)
	// Result depends on actual system state; just verify no error/panic
	t.Logf("hotpatch enabled: %v (build=%s, productType=%s)", result, ver.CurrentBuild, ver.ProductType)
}

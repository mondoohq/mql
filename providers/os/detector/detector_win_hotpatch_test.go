// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	win "go.mondoo.com/mql/providers/os/detector/windows"
	"go.mondoo.com/mql/providers/os/registry"
)

// TestWindowsHotpatchLabels covers the labels on the live detection path. The
// eligible label follows OS, edition, build and architecture only; the
// hotpatch label additionally needs enrollment (servers) or configuration
// (clients).
func TestWindowsHotpatchLabels(t *testing.T) {
	cases := []struct {
		fixture  string
		eligible string
		hotpatch string
	}{
		{"detect-windows2025-hotpatch.toml", "true", "true"},
		{"detect-azure-windows2025.toml", "true", "false"},
		{"detect-windows2025.toml", "true", "false"},
		{"detect-windows2022.toml", "true", "false"},
		{"detect-windows11-24h2.toml", "true", "false"},
		{"detect-windows11-24h2-hotpatch.toml", "true", "true"},
		{"detect-windows11-24h2-pro-hotpatch.toml", "true", "true"},
		{"detect-windows2019.toml", "false", "false"},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			di, err := detectPlatformFromMock("./testdata/" + tc.fixture)
			require.NoError(t, err)
			assert.Equal(t, tc.eligible, di.Labels[win.HotpatchEligibleLabel])
			assert.Equal(t, tc.hotpatch, di.Labels[win.HotpatchLabel])
		})
	}
}

// hotpatchHive serves SOFTWARE and SYSTEM hives loaded from files, keyed by
// "<hive>|<path>", with ControlSet001 active.
type hotpatchHive map[string][]registry.RegistryKeyItem

func (h hotpatchHive) GetRegistryItemValue(id, path, key string) (registry.RegistryKeyItem, error) {
	return registry.RegistryKeyItem{}, errors.New("not found")
}

func (h hotpatchHive) GetNativeRegistryKeyItems(id, path string) ([]registry.RegistryKeyItem, error) {
	if items, ok := h[id+"|"+path]; ok {
		return items, nil
	}
	return nil, errors.New("key not found")
}

func hiveDword(name, v string) registry.RegistryKeyItem {
	return registry.RegistryKeyItem{Key: name, Value: registry.RegistryKeyValue{Kind: registry.DWORD, String: v}}
}

// TestStaticHotpatchLabels covers the labels on the offline detection path,
// where the VBS running state cannot be read and the configured value decides.
func TestStaticHotpatchLabels(t *testing.T) {
	sw := registry.Software + "|"
	sys := registry.System + "|"
	enrolledServer := hotpatchHive{
		sw + `Microsoft\Windows NT\CurrentVersion\Update\TargetingInfo\DynamicInstalled\Hotpatch.amd64`: {{Key: "Name", Value: registry.RegistryKeyValue{Kind: registry.SZ, String: win.HotpatchPackage}}},
		sys + `ControlSet001\Control\DeviceGuard`:                                                       {hiveDword("EnableVirtualizationBasedSecurity", "1")},
		sys + `ControlSet001\Control\Session Manager\Memory Management`:                                 {hiveDword("HotPatchTableSize", "4096")},
	}
	configuredClient := hotpatchHive{
		sw + `Microsoft\PolicyManager\current\device\Update`: {hiveDword("AllowRebootlessUpdates", "1")},
		sys + `ControlSet001\Control\DeviceGuard`:            {hiveDword("EnableVirtualizationBasedSecurity", "1")},
	}

	server := func(version string) *inventory.Platform {
		return &inventory.Platform{Title: "Windows Server", Version: version, Build: "1000", Arch: "AMD64", Labels: map[string]string{"windows.mondoo.com/product-type": "3"}}
	}
	client := func(title, version, build string) *inventory.Platform {
		return &inventory.Platform{Title: title, Version: version, Build: build, Arch: "AMD64", Labels: map[string]string{"windows.mondoo.com/product-type": "1"}}
	}

	cases := []struct {
		name     string
		pf       *inventory.Platform
		hive     hotpatchHive
		eligible string
		hotpatch string
	}{
		{"enrolled Server 2022", server("20348"), enrolledServer, "true", "true"},
		{"Server 2022 without enrollment", server("20348"), hotpatchHive{}, "true", "false"},
		{"configured Windows 11 24H2", client("Windows 11 Enterprise", "26100", "3000"), configuredClient, "true", "true"},
		{"Windows 11 24H2 without configuration", client("Windows 11 Enterprise", "26100", "3000"), hotpatchHive{}, "true", "false"},
		{"Windows 11 Home is not eligible", client("Windows 11 Home", "26100", "3000"), hotpatchHive{}, "false", "false"},
		// The offline hotpatch label is not gated on eligibility, as before.
		{"configured Windows 11 23H2", client("Windows 11 Enterprise", "22631", "4000"), configuredClient, "false", "true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			applyStaticHotpatch(tc.pf, tc.hive)
			assert.Equal(t, tc.eligible, tc.pf.Labels[win.HotpatchEligibleLabel])
			assert.Equal(t, tc.hotpatch, tc.pf.Labels[win.HotpatchLabel])
		})
	}

	t.Run("no eligible label without a product type", func(t *testing.T) {
		pf := &inventory.Platform{Version: "20348", Labels: map[string]string{}}
		applyStaticHotpatch(pf, hotpatchHive{})
		_, ok := pf.Labels[win.HotpatchEligibleLabel]
		assert.False(t, ok)
	})
}

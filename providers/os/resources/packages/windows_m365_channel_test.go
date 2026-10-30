// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

func TestM365ChannelFromValue(t *testing.T) {
	tests := []struct {
		value     string
		channel   string
		isChannel bool
	}{
		// CDN urls, the common form of CDNBaseUrl / UpdateChannel
		{"http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60", "current", true},
		{"https://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6", "monthly-enterprise", true},
		{"http://officecdn.microsoft.com/pr/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114/", "semi-annual-enterprise", true},
		{"http://officecdn.microsoft.com/pr/b8f9b850-328d-4355-9145-c59439a0c4cf", "semi-annual-enterprise-preview", true},
		{"http://officecdn.microsoft.com/pr/64256afe-f5d9-4f86-8936-8840a6a4f5be", "current-preview", true},
		{"http://officecdn.microsoft.com/pr/5440fd1f-7ecb-4221-8110-145efaa6372f", "beta", true},
		// bare audience ids, including the mixed-case form
		{"492350f6-3a01-4f97-b9c0-c7c6ddf67d60", "current", true},
		{"55336B82-A18D-4DD6-B5F6-9E5095C314A6", "monthly-enterprise", true},
		// an audience we don't know still NAMES a channel: no qualifier, and
		// the caller must not fall back to a lower-priority value
		{"http://officecdn.microsoft.com/pr/00000000-0000-0000-0000-000000000000", "", true},
		{"00000000-0000-0000-0000-000000000000", "", true},
		// values that name no channel at all — the caller keeps looking
		{"\\\\fileserver\\office\\updates", "", false},
		{"http://sccm.corp.example.com/office/updates", "", false},
		{"Current", "", false},
		{"   ", "", false},
		{"", "", false},
	}

	for _, test := range tests {
		channel, isChannel := m365ChannelFromValue(test.value)
		assert.Equal(t, test.channel, channel, test.value)
		assert.Equal(t, test.isChannel, isChannel, test.value)
	}
}

func TestIsM365AppsPackage(t *testing.T) {
	clickToRun := []string{
		"Microsoft 365 Apps for enterprise - en-us",
		"Microsoft 365 Apps for business - de-de",
		"Microsoft 365 - en-us",
		"Microsoft Office 365 ProPlus - en-us",
		"Microsoft Office 365 Business - en-us",
		// retail / consumer Click-to-Run, which registers without a SKU word
		"Microsoft Office 365 - en-us",
	}
	for _, name := range clickToRun {
		assert.True(t, isM365AppsPackage(name), name)
	}

	// MSI-installed Office has no update channel, neither do unrelated packages
	other := []string{
		"Microsoft Office Professional Plus 2016",
		"Microsoft Office LTSC Professional Plus 2021 - en-us",
		"Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29913",
		"Microsoft Edge",
		"",
	}
	for _, name := range other {
		assert.False(t, isM365AppsPackage(name), name)
	}
}

func TestM365ChannelFromRegistryItems(t *testing.T) {
	item := func(key, value string) registry.RegistryKeyItem {
		return registry.RegistryKeyItem{Key: key, Value: registry.RegistryKeyValue{String: value}}
	}

	t.Run("prefers CDNBaseUrl over the assigned channel", func(t *testing.T) {
		// a device that was moved to Monthly Enterprise but still runs the
		// build it installed from Current Channel
		items := []registry.RegistryKeyItem{
			item("VersionToReport", "16.0.20131.20154"),
			item("UpdateChannel", "http://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6"),
			item("CDNBaseUrl", "http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60"),
		}
		assert.Equal(t, "current", m365ChannelFromRegistryItems(items))
	})

	t.Run("falls back to the assigned channel", func(t *testing.T) {
		items := []registry.RegistryKeyItem{
			item("UpdateUrl", "http://officecdn.microsoft.com/pr/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114"),
		}
		assert.Equal(t, "semi-annual-enterprise", m365ChannelFromRegistryItems(items))
	})

	t.Run("skips values that carry no channel", func(t *testing.T) {
		items := []registry.RegistryKeyItem{
			item("CDNBaseUrl", ""),
			item("UpdateUrl", "\\\\fileserver\\office\\updates"),
			item("UnmanagedUpdateURL", "http://officecdn.microsoft.com/pr/5440fd1f-7ecb-4221-8110-145efaa6372f"),
		}
		assert.Equal(t, "beta", m365ChannelFromRegistryItems(items))
	})

	t.Run("an unknown audience does not fall through to the assigned channel", func(t *testing.T) {
		// the installed bits came from a channel this build doesn't know;
		// reporting the policy-assigned Current Channel instead would claim a
		// channel the build never came from
		items := []registry.RegistryKeyItem{
			item("CDNBaseUrl", "http://officecdn.microsoft.com/pr/00000000-0000-0000-0000-000000000000"),
			item("UpdateChannel", "http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60"),
		}
		assert.Equal(t, "", m365ChannelFromRegistryItems(items))
	})

	t.Run("value names are matched case-insensitively", func(t *testing.T) {
		items := []registry.RegistryKeyItem{
			item("cdnbaseurl", "http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60"),
		}
		assert.Equal(t, "current", m365ChannelFromRegistryItems(items))
	})

	t.Run("no ClickToRun values at all", func(t *testing.T) {
		assert.Equal(t, "", m365ChannelFromRegistryItems(nil))
	})
}

func TestM365ChannelFromKeys(t *testing.T) {
	current := []registry.RegistryKeyItem{
		{Key: "CDNBaseUrl", Value: registry.RegistryKeyValue{String: "http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60"}},
	}

	t.Run("reads each key exactly once", func(t *testing.T) {
		reads := []string{}
		channel := m365ChannelFromKeys(officeC2RConfigKeys, func(path string) ([]registry.RegistryKeyItem, error) {
			reads = append(reads, path)
			return nil, nil
		})

		assert.Equal(t, "", channel)
		assert.Equal(t, officeC2RConfigKeys, reads)
	})

	t.Run("falls through to the Wow6432Node view", func(t *testing.T) {
		channel := m365ChannelFromKeys(officeC2RConfigKeys, func(path string) ([]registry.RegistryKeyItem, error) {
			if strings.Contains(path, "WOW6432Node") {
				return current, nil
			}
			return nil, errors.New("registry key not found")
		})

		assert.Equal(t, "current", channel)
	})
}

func TestOfficeC2RConfigKeys(t *testing.T) {
	// the live-registry paths are derived from the hive-relative ones, so the
	// two readers can never probe different keys
	assert.Equal(t, []string{
		"HKLM\\SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration",
		"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Office\\ClickToRun\\Configuration",
	}, officeC2RConfigKeys)
}

func TestApplyM365ChannelQualifier(t *testing.T) {
	pf := &inventory.Platform{
		Name:    "windows",
		Version: "10.0.26100",
		Arch:    "x86_64",
		Family:  []string{"windows"},
	}

	newPkgs := func() []Package {
		return []Package{
			*createPackage("Microsoft 365 Apps for enterprise - en-us", "16.0.20131.20154", "windows/app", pf.Arch, "Microsoft Corporation", "", pf),
			*createPackage("Microsoft Edge", "140.0.3485.14", "windows/app", pf.Arch, "Microsoft Corporation", "", pf),
		}
	}

	t.Run("stamps the channel on M365 Apps only", func(t *testing.T) {
		pkgs := newPkgs()
		edgePurl := pkgs[1].PUrl

		applyM365ChannelQualifier(pkgs, pf, func() string { return "monthly-enterprise" })

		assert.Contains(t, pkgs[0].PUrl, "channel=monthly-enterprise")
		assert.Contains(t, pkgs[0].PUrl, "@16.0.20131.20154")
		assert.Equal(t, edgePurl, pkgs[1].PUrl, "unrelated packages keep their purl")
	})

	t.Run("keeps the plain purl when the channel is unknown", func(t *testing.T) {
		pkgs := newPkgs()
		plainPurl := pkgs[0].PUrl

		applyM365ChannelQualifier(pkgs, pf, func() string { return "" })

		assert.Equal(t, plainPurl, pkgs[0].PUrl)
		assert.NotContains(t, pkgs[0].PUrl, "channel=")
	})

	t.Run("does not probe the registry without an M365 Apps package", func(t *testing.T) {
		pkgs := newPkgs()[1:]
		probed := false

		applyM365ChannelQualifier(pkgs, pf, func() string {
			probed = true
			return "current"
		})

		assert.False(t, probed)
	})
}

// TestGetInstalledAppsM365Channel exercises the remote (PowerShell) collection
// path end to end: the app list and the ClickToRun configuration are read over
// the same connection, and the channel lands on the M365 Apps purl.
func TestGetInstalledAppsM365Channel(t *testing.T) {
	const installedApps = `[
	  {"DisplayName":"Microsoft 365 Apps for enterprise - en-us","DisplayVersion":"16.0.20131.20154","Publisher":"Microsoft Corporation","UninstallString":"\"C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe\"","PSPath":"Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\O365ProPlusRetail - en-us"},
	  {"DisplayName":"Microsoft Edge","DisplayVersion":"140.0.3485.14","Publisher":"Microsoft Corporation","UninstallString":"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\140.0.3485.14\\Installer\\setup.exe","PSPath":"Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Edge"}
	]`

	c2rCmd := powershell.Encode(registry.GetRegistryKeyItemScript(officeC2RConfigKeys[0]))
	c2rItems := regItemsJSON(t,
		szItem("VersionToReport", "16.0.20131.20154"),
		szItem("CDNBaseUrl", "http://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6"),
	)

	tests := []struct {
		name        string
		c2rStdout   string
		wantChannel string
	}{
		{
			name:        "ClickToRun configuration readable",
			c2rStdout:   c2rItems,
			wantChannel: "monthly-enterprise",
		},
		{
			// no ClickToRun key (or the read was denied) — the package keeps
			// its plain purl instead of dropping out
			name:        "ClickToRun configuration missing",
			c2rStdout:   "",
			wantChannel: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commands := map[string]snapCommandResult{
				powershell.Encode(installedAppsScript): {stdout: installedApps},
			}
			if tt.c2rStdout != "" {
				commands[c2rCmd] = snapCommandResult{stdout: tt.c2rStdout}
			}

			w := &WinPkgManager{
				conn: &snapTestConnection{
					capabilities: shared.Capability_RunCommand,
					commands:     commands,
				},
				platform: &inventory.Platform{Name: "windows", Version: "10.0.26100", Arch: "x86_64", Family: []string{"windows"}},
			}

			pkgs, err := w.getInstalledApps()
			require.NoError(t, err)
			require.Len(t, pkgs, 2)

			m365 := findPkgByName(pkgs, "Microsoft 365 Apps for enterprise - en-us")
			require.NotNil(t, m365)
			if tt.wantChannel == "" {
				assert.NotContains(t, m365.PUrl, "channel=")
			} else {
				assert.Contains(t, m365.PUrl, "channel="+tt.wantChannel)
			}

			edge := findPkgByName(pkgs, "Microsoft Edge")
			require.NotNil(t, edge)
			assert.NotContains(t, edge.PUrl, "channel=")
		})
	}
}

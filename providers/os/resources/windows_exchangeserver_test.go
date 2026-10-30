// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/registry"
)

func TestExchangeVersionAndInstallPath(t *testing.T) {
	// The values Exchange Server 2019 CU15 setup writes under
	// HKLM\SOFTWARE\Microsoft\ExchangeServer\v15\Setup (build 15.2.1544.4).
	items := map[string]registry.RegistryKeyItem{
		"msiinstallpath":  {Key: "MsiInstallPath", Value: registry.RegistryKeyValue{Kind: registry.SZ, String: `C:\Program Files\Microsoft\Exchange Server\V15\`}},
		"msiproductmajor": {Key: "MsiProductMajor", Value: registry.RegistryKeyValue{Kind: registry.DWORD, Number: 15}},
		"msiproductminor": {Key: "MsiProductMinor", Value: registry.RegistryKeyValue{Kind: registry.DWORD, Number: 2}},
		"msibuildmajor":   {Key: "MsiBuildMajor", Value: registry.RegistryKeyValue{Kind: registry.DWORD, Number: 1544}},
		"msibuildminor":   {Key: "MsiBuildMinor", Value: registry.RegistryKeyValue{Kind: registry.DWORD, Number: 4}},
	}
	assert.Equal(t, "15.2.1544.4", exchangeVersion(items))
	assert.Equal(t, `C:\Program Files\Microsoft\Exchange Server\V15`, exchangeInstallPath(items))

	partial := map[string]registry.RegistryKeyItem{
		"msiproductmajor": items["msiproductmajor"],
		"msiproductminor": items["msiproductminor"],
	}
	assert.Equal(t, "", exchangeVersion(partial), "an interrupted setup has no build, not 15.2.0.0")

	empty := map[string]registry.RegistryKeyItem{}
	assert.Equal(t, "", exchangeVersion(empty), "no version on a host without Exchange, not 0.0.0.0")
	assert.Equal(t, "", exchangeInstallPath(empty))
}

// The organization-wide settings hang off singular sub-resources named exactly
// like the fields that reach them. Without an Init, asking for
// windows.exchangeServer.transportConfig by its own path would report null for
// every field instead of the organization's settings.
func TestWindowsExchangeServerSingletonsAreReachableByTheirOwnPath(t *testing.T) {
	paths := []string{
		"windows.exchangeServer.organizationConfig",
		"windows.exchangeServer.transportConfig",
		"windows.exchangeServer.adminAuditLogConfig",
		"windows.exchangeServer.contentFilterConfig",
		"windows.exchangeServer.senderFilterConfig",
		"windows.exchangeServer.senderIdConfig",
		"windows.exchangeServer.senderReputationConfig",
		"windows.exchangeServer.recipientFilterConfig",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			_, isField := getDataFields[path]
			require.True(t, isField, "%s should be a field path on its parent", path)
			factory, isResource := resourceFactories[path]
			require.True(t, isResource, "%s should also be a registered resource name", path)
			assert.NotNil(t, factory.Init, "%s needs an Init that delegates to the parent", path)
		})
	}
}

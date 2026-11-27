// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/fastly.json so the CLI and generated docs can list what
// the provider supports.
var Platforms = []*plugin.PlatformInfo{
	{Name: "fastly", Title: "Fastly Account", Family: []string{"fastly"}, Kind: []string{"api"}, Runtime: []string{"fastly"}},
}

const platformIdFastlyAccount = "//platformid.api.mondoo.app/runtime/fastly/customer/"

// NewFastlyAccountPlatform returns the platform for a Fastly account asset.
func NewFastlyAccountPlatform(customerID string) *inventory.Platform {
	return &inventory.Platform{
		Name:                  "fastly",
		Title:                 "Fastly Account",
		Family:                []string{"fastly"},
		Kind:                  "api",
		Runtime:               "fastly",
		TechnologyUrlSegments: []string{"saas", "fastly", customerID},
	}
}

// NewFastlyAccountIdentifier returns the stable platform id for an account.
func NewFastlyAccountIdentifier(customerID string) string {
	return platformIdFastlyAccount + customerID
}

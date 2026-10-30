// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	DiscoveryAll      = "all"
	DiscoveryAuto     = "auto"
	DiscoveryAccounts = "accounts"
	DiscoverySites    = "sites"
)

const (
	PlatformIdNetlifyAccount = "//platformid.api.mondoo.app/runtime/netlify/account/"
	PlatformIdNetlifySite    = "//platformid.api.mondoo.app/runtime/netlify/site/"
)

func NewNetlifyAccountPlatform(accountID string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "netlify", "account", accountID},
	}
	PlatformByName("netlify-account").Apply(pf)
	return pf
}

func NewNetlifySitePlatform(accountID, siteID string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "netlify", "account", accountID, "site", siteID},
	}
	PlatformByName("netlify-site").Apply(pf)
	return pf
}

func NewNetlifyAccountIdentifier(accountID string) string {
	return PlatformIdNetlifyAccount + accountID
}

func NewNetlifySiteIdentifier(siteID string) string {
	return PlatformIdNetlifySite + siteID
}

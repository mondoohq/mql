// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package connection

import (
	"errors"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	DiscoveryAll      = "all"
	DiscoveryAuto     = "auto"
	DiscoveryZones    = "zones"
	DiscoveryAccounts = "accounts"
)

var (
	PlatformIdCloudflareZone    = "//platformid.api.mondoo.app/runtime/cloudflare/zone/"
	PlatformIdCloudflareAccount = "//platformid.api.mondoo.app/runtime/cloudflare/account/"
)

func (c *CloudflareConnection) PlatformInfo() (*inventory.Platform, error) {
	conf := c.asset.Connections[0]
	if zoneName := conf.Options["zone"]; zoneName != "" {
		return NewCloudflareZonePlatform(zoneName), nil
	}
	if accountName := conf.Options["account"]; accountName != "" {
		return NewCloudflareAccountPlatform(accountName), nil
	}

	return nil, errors.New("could not detect Cloudflare asset type")
}

func NewCloudflareZonePlatform(zoneId string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "cloudflare", "zone", zoneId},
	}
	PlatformByName("cloudflare-zone").Apply(pf)
	return pf
}

func NewCloudflareAccountPlatform(accountId string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "cloudflare", "account", accountId},
	}
	PlatformByName("cloudflare-account").Apply(pf)
	return pf
}

func NewCloudflareZoneIdentifier(zoneId string) string {
	return PlatformIdCloudflareZone + zoneId
}

func NewCloudflareAccountIdentifier(accountId string) string {
	return PlatformIdCloudflareAccount + accountId
}

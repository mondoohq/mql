// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/utils/stringx"
)

func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.CloudflareConnection)

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}

	targets := handleTargets(conn.Asset().Connections[0].Discover.Targets)
	list, err := discover(runtime, targets)
	if err != nil {
		return in, err
	}

	in.Spec.Assets = list
	return in, nil
}

func handleTargets(targets []string) []string {
	if stringx.ContainsAnyOf(targets, connection.DiscoveryAll, connection.DiscoveryAuto) {
		return []string{
			connection.DiscoveryAccounts,
			connection.DiscoveryZones,
		}
	}
	return targets
}

func discover(runtime *plugin.Runtime, targets []string) ([]*inventory.Asset, error) {
	conn := runtime.Connection.(*connection.CloudflareConnection)
	conf := conn.Asset().Connections[0]
	assetList := []*inventory.Asset{}

	cf, err := getMqlCloudflare(runtime)
	if err != nil {
		return nil, err
	}

	for _, target := range targets {
		switch target {
		case connection.DiscoveryZones:
			zones, err := cf.zones()
			if err != nil {
				return nil, err
			}

			for _, izone := range zones {
				zone := izone.(*mqlCloudflareZone)
				asset := &inventory.Asset{
					PlatformIds: []string{connection.NewCloudflareZoneIdentifier(zone.Id.Data)},
					Name:        zone.Name.Data,
					Platform:    connection.NewCloudflareZonePlatform(zone.Id.Data),
					Labels:      map[string]string{},
					Connections: []*inventory.Config{conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))},
				}
				assetList = append(assetList, asset)
			}
		case connection.DiscoveryAccounts:
			accounts, err := cf.accounts()
			if err != nil {
				return nil, err
			}

			for _, iaccount := range accounts {
				account := iaccount.(*mqlCloudflareAccount)
				asset := &inventory.Asset{
					PlatformIds: []string{connection.NewCloudflareAccountIdentifier(account.Id.Data)},
					Name:        account.Name.Data,
					Platform:    connection.NewCloudflareAccountPlatform(account.Id.Data),
					Labels:      map[string]string{},
					Connections: []*inventory.Config{conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))},
				}
				assetList = append(assetList, asset)
			}
		default:
			continue
		}
	}

	return assetList, nil
}

func getMqlCloudflare(runtime *plugin.Runtime) (*mqlCloudflare, error) {
	res, err := createCloudflare(runtime, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}

	return res.(*mqlCloudflare), nil
}

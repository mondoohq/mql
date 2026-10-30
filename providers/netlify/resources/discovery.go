// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/netlify/connection"
	"go.mondoo.com/mql/utils/stringx"
)

func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := netlifyConn(runtime)

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
			connection.DiscoverySites,
		}
	}
	return targets
}

func discover(runtime *plugin.Runtime, targets []string) ([]*inventory.Asset, error) {
	conn := netlifyConn(runtime)
	conf := conn.Asset().Connections[0]

	wantAccounts := stringx.Contains(targets, connection.DiscoveryAccounts)
	wantSites := stringx.Contains(targets, connection.DiscoverySites)
	if !wantAccounts && !wantSites {
		return nil, nil
	}

	root, err := getNetlify(runtime)
	if err != nil {
		return nil, err
	}

	// The account list already honors the --account flag, so discovery emits
	// assets for exactly the accounts a plain query would see.
	accounts, err := root.accounts()
	if err != nil {
		return nil, err
	}

	assetList := []*inventory.Asset{}
	for _, it := range accounts {
		account := it.(*mqlNetlifyAccount)
		accountID := account.Id.Data
		accountName := account.Name.Data
		if accountName == "" {
			accountName = account.Slug.Data
		}

		if wantAccounts {
			assetList = append(assetList, &inventory.Asset{
				PlatformIds: []string{connection.NewNetlifyAccountIdentifier(accountID)},
				Name:        accountName,
				Platform:    connection.NewNetlifyAccountPlatform(accountID),
				Labels:      map[string]string{},
				Connections: []*inventory.Config{scopedConfig(conf, conn.ID(), accountID, "")},
			})
		}

		if wantSites {
			sites := account.GetSites()
			if sites.Error != nil {
				return nil, sites.Error
			}
			for _, sit := range sites.Data {
				site := sit.(*mqlNetlifySite)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{connection.NewNetlifySiteIdentifier(site.Id.Data)},
					Name:        site.Name.Data,
					Platform:    connection.NewNetlifySitePlatform(accountID, site.Id.Data),
					Labels:      map[string]string{},
					Connections: []*inventory.Config{scopedConfig(conf, conn.ID(), accountID, site.Id.Data)},
				})
			}
		}
	}

	return assetList, nil
}

// scopedConfig clones the parent connection config for a discovered child
// asset, stamping the account (and optional site) it is scoped to.
func scopedConfig(conf *inventory.Config, parentID uint32, accountID, siteID string) *inventory.Config {
	child := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(parentID))
	options := map[string]string{"accountId": accountID}
	if account := conf.Options["account"]; account != "" {
		options["account"] = account
	}
	if siteID != "" {
		options["siteId"] = siteID
	}
	child.Options = options
	return child
}

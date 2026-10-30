// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"maps"

	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/openstack/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// Discover expands the connected OpenStack scope into the child assets the
// discovery targets ask for. The scope (project/domain/system) stays the
// connected root asset; the returned inventory holds the children.
func Discover(runtime *plugin.Runtime) (*inventory.Inventory, error) {
	c := conn(runtime)
	conf := c.Asset().Connections[0]
	if conf.Discover == nil || len(conf.Discover.Targets) == 0 {
		return nil, nil
	}
	targets := resolveDiscoveryTargets(conf.Discover.Targets)

	assets := []*inventory.Asset{}

	// childAsset clones the parent connection (discovery off, parented to this
	// connection) and stamps the per-child scoping options onto it.
	childAsset := func(platform *inventory.Platform, platformID, name string, opts map[string]string) *inventory.Asset {
		cfg := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(c.ID()))
		maps.Copy(cfg.Options, opts)
		return &inventory.Asset{
			PlatformIds: []string{platformID},
			Name:        name,
			Platform:    platform,
			Connections: []*inventory.Config{cfg},
		}
	}

	if stringx.Contains(targets, connection.DiscoverySecurityGroups) {
		client, err := c.NetworkClient()
		if err != nil {
			return nil, err
		}
		pages, err := groups.List(client, groups.ListOpts{}).AllPages(ctx())
		if err != nil {
			// A scope without the network service (or without access) simply
			// yields no security-group children rather than failing the scan.
			if translateOpenstackError(err) == nil {
				return &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: assets}}, nil
			}
			return nil, err
		}
		items, err := groups.ExtractGroups(pages)
		if err != nil {
			return nil, err
		}
		for i := range items {
			sg := &items[i]
			name := sg.Name
			if name == "" {
				name = sg.ID
			}
			assets = append(assets, childAsset(
				connection.SecurityGroupPlatform(),
				c.NewSecurityGroupIdentifier(sg.ID),
				"OpenStack Security Group "+name,
				map[string]string{connection.OptionSecurityGroup: sg.ID},
			))
		}
	}

	return &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: assets}}, nil
}

// resolveDiscoveryTargets normalizes the requested targets. "all" expands to
// every supported child type; "auto" (the default) matches nothing here, so a
// plain connection stays a single root asset.
func resolveDiscoveryTargets(targets []string) []string {
	if stringx.Contains(targets, connection.DiscoveryAll) {
		return []string{connection.DiscoverySecurityGroups}
	}
	return targets
}

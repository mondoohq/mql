// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/exoscale/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// discoveredChild is one child asset found by a discovery target.
type discoveredChild struct {
	sub  connection.SubAsset
	id   string // value of the sub-asset option
	zone string // set for resources keyed within a zone
	name string
}

// Discover expands an organization connection into the child assets the
// discovery targets ask for. The organization stays the connected (root)
// asset; the returned inventory holds the children.
func Discover(runtime *plugin.Runtime) (*inventory.Inventory, error) {
	c := conn(runtime)
	conf := c.Asset().Connections[0]
	if conf.Discover == nil || len(conf.Discover.Targets) == 0 {
		return nil, nil
	}
	// A connection already scoped to a child asset does not discover further.
	if _, _, ok := c.SubAsset(); ok {
		return nil, nil
	}

	targets := resolveDiscoveryTargets(conf.Discover.Targets)
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}

	subAsset := func(option string) connection.SubAsset {
		for _, s := range connection.SubAssets {
			if s.Option == option {
				return s
			}
		}
		panic("unknown sub-asset option " + option)
	}

	var children []discoveredChild
	if stringx.Contains(targets, connection.DiscoveryInstances) {
		list := ns.GetInstances()
		if list.Error != nil {
			return nil, list.Error
		}
		for _, e := range list.Data {
			r := e.(*mqlExoscaleComputeInstance)
			children = append(children, discoveredChild{subAsset(connection.OptionInstance), r.Id.Data, "", r.Name.Data})
		}
	}
	if stringx.Contains(targets, connection.DiscoverySecurityGroups) {
		list := ns.GetSecurityGroups()
		if list.Error != nil {
			return nil, list.Error
		}
		for _, e := range list.Data {
			r := e.(*mqlExoscaleSecurityGroup)
			children = append(children, discoveredChild{subAsset(connection.OptionSecurityGroup), r.Id.Data, "", r.Name.Data})
		}
	}
	if stringx.Contains(targets, connection.DiscoverySksClusters) {
		list := ns.GetSksClusters()
		if list.Error != nil {
			return nil, list.Error
		}
		for _, e := range list.Data {
			r := e.(*mqlExoscaleSksCluster)
			children = append(children, discoveredChild{subAsset(connection.OptionSksCluster), r.Id.Data, "", r.Name.Data})
		}
	}
	if stringx.Contains(targets, connection.DiscoveryNlbs) {
		list := ns.GetNlbs()
		if list.Error != nil {
			return nil, list.Error
		}
		for _, e := range list.Data {
			r := e.(*mqlExoscaleNlb)
			children = append(children, discoveredChild{subAsset(connection.OptionNlb), r.Id.Data, "", r.Name.Data})
		}
	}
	if stringx.Contains(targets, connection.DiscoveryDbaasServices) {
		list := ns.GetDbaasServices()
		if list.Error != nil {
			return nil, list.Error
		}
		for _, e := range list.Data {
			r := e.(*mqlExoscaleDbaasService)
			children = append(children, discoveredChild{subAsset(connection.OptionDbaasService), r.Name.Data, r.Zone.Data, r.Name.Data})
		}
	}

	assets := make([]*inventory.Asset, 0, len(children))
	for _, ch := range children {
		cfg := childConfig(conf, c.ID(), ch)
		platformID := c.SubAssetIdentifier(ch.sub, ch.zone, ch.id)
		assets = append(assets, &inventory.Asset{
			PlatformIds: []string{platformID},
			Name:        ch.sub.Title + " " + ch.name,
			Platform:    ch.sub.NewPlatform(),
			Connections: []*inventory.Config{cfg},
		})
	}
	return &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: assets}}, nil
}

// childConfig clones the organization's config for a child asset and stamps
// the child's discriminating options. Config.Clone leaves Options nil when the
// source had none, so guard before writing.
func childConfig(conf *inventory.Config, parentID uint32, ch discoveredChild) *inventory.Config {
	cfg := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(parentID))
	if cfg.Options == nil {
		cfg.Options = map[string]string{}
	}
	cfg.Options[ch.sub.Option] = ch.id
	if ch.zone != "" {
		cfg.Options[connection.OptionZone] = ch.zone
	}
	return cfg
}

// resolveDiscoveryTargets expands the "auto"/"all" aliases.
func resolveDiscoveryTargets(targets []string) []string {
	if stringx.Contains(targets, connection.DiscoveryAll) || stringx.Contains(targets, connection.DiscoveryAuto) {
		return []string{
			connection.DiscoveryInstances,
			connection.DiscoverySecurityGroups,
			connection.DiscoverySksClusters,
			connection.DiscoveryNlbs,
			connection.DiscoveryDbaasServices,
		}
	}
	return targets
}

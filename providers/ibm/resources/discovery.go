// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ibm/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// discoveredChild is one child asset found by a discovery target.
type discoveredChild struct {
	sub    connection.SubAsset
	crn    string
	name   string
	region string
}

// Discover expands an account connection into the child assets the discovery
// targets ask for. The account stays the connected (root) asset; the returned
// inventory holds the children.
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
	sub := func(option string) connection.SubAsset {
		for _, s := range connection.SubAssets {
			if s.Option == option {
				return s
			}
		}
		panic("unknown sub-asset option " + option)
	}
	// A target whose list fails is skipped rather than aborting discovery:
	// the account asset still scans and reports the error on the field.
	skipTarget := func(err error) {
		log.Warn().Err(err).Msg("ibm> discovery target failed, skipping")
	}

	var children []discoveredChild
	if stringx.Contains(targets, connection.DiscoveryVpcInstances) {
		list := ns.GetVpcInstances()
		if list.Error != nil {
			skipTarget(list.Error)
		} else {
			for _, e := range list.Data {
				i := e.(*mqlIbmVpcInstance)
				children = append(children, discoveredChild{sub(connection.OptionVpcInstance), i.Crn.Data, i.Name.Data, i.Region.Data})
			}
		}
	}
	if stringx.Contains(targets, connection.DiscoveryVpcSecurityGroups) {
		list := ns.GetVpcSecurityGroups()
		if list.Error != nil {
			skipTarget(list.Error)
		} else {
			for _, e := range list.Data {
				sg := e.(*mqlIbmVpcSecurityGroup)
				children = append(children, discoveredChild{sub(connection.OptionVpcSecurityGroup), sg.Crn.Data, sg.Name.Data, sg.Region.Data})
			}
		}
	}
	if stringx.Contains(targets, connection.DiscoveryPowerWorkspaces) {
		list := ns.GetPowerWorkspaces()
		if list.Error != nil {
			skipTarget(list.Error)
		} else {
			for _, e := range list.Data {
				w := e.(*mqlIbmPowerWorkspace)
				children = append(children, discoveredChild{sub(connection.OptionPowerWorkspace), w.Crn.Data, w.Name.Data, w.Zone.Data})
			}
		}
	}

	assets := make([]*inventory.Asset, 0, len(children))
	for _, ch := range children {
		cfg := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(c.ID()))
		if cfg.Options == nil {
			cfg.Options = map[string]string{}
		}
		cfg.Options[ch.sub.Option] = ch.crn
		assets = append(assets, &inventory.Asset{
			PlatformIds: []string{c.SubAssetIdentifier(ch.sub, ch.crn)},
			Name:        ch.sub.Title + " " + ch.name,
			Platform:    ch.sub.NewPlatform(),
			Labels:      childLabels(ch, c.Identifier()),
			Connections: []*inventory.Config{cfg},
		})
	}
	return &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: assets}}, nil
}

func childLabels(ch discoveredChild, parentID string) map[string]string {
	out := map[string]string{"mondoo.com/parent-id": parentID}
	if ch.region != "" {
		out["mondoo.com/region"] = ch.region
	}
	return out
}

// resolveDiscoveryTargets expands the "auto"/"all" aliases.
func resolveDiscoveryTargets(targets []string) []string {
	if stringx.Contains(targets, connection.DiscoveryAll) || stringx.Contains(targets, connection.DiscoveryAuto) {
		return []string{
			connection.DiscoveryVpcInstances,
			connection.DiscoveryVpcSecurityGroups,
			connection.DiscoveryPowerWorkspaces,
		}
	}
	return targets
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/hetzner/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// Discover expands a Hetzner Cloud project connection into the specific
// child assets the discovery targets ask for. The project itself stays
// the connected (root) asset; the returned inventory holds the children.
func Discover(runtime *plugin.Runtime) (*inventory.Inventory, error) {
	c := conn(runtime)
	conf := c.Asset().Connections[0]
	if conf.Discover == nil || len(conf.Discover.Targets) == 0 {
		return nil, nil
	}

	targets := resolveDiscoveryTargets(conf.Discover.Targets)
	assets := []*inventory.Asset{}

	childAsset := func(platform *inventory.Platform, platformID, name, optKey, optVal string) *inventory.Asset {
		cfg := childConfig(conf, c.ID(), optKey, optVal)
		return &inventory.Asset{
			PlatformIds: []string{platformID},
			Name:        name,
			Platform:    platform,
			Connections: []*inventory.Config{cfg},
		}
	}

	if stringx.Contains(targets, connection.DiscoveryFirewalls) {
		items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.Firewall, *hcloud.Response, error) {
			return c.Client().Firewall.List(ctx(), hcloud.FirewallListOpts{ListOpts: opts})
		})
		if err != nil {
			return nil, err
		}
		for _, fw := range items {
			idStr := strconv.FormatInt(fw.ID, 10)
			assets = append(assets, childAsset(
				connection.FirewallPlatform(),
				c.NewFirewallIdentifier(idStr),
				"Hetzner Firewall "+fw.Name,
				connection.OptionFirewall, idStr,
			))
		}
	}

	if stringx.Contains(targets, connection.DiscoveryLoadBalancers) {
		items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.LoadBalancer, *hcloud.Response, error) {
			return c.Client().LoadBalancer.List(ctx(), hcloud.LoadBalancerListOpts{ListOpts: opts})
		})
		if err != nil {
			return nil, err
		}
		for _, lb := range items {
			idStr := strconv.FormatInt(lb.ID, 10)
			assets = append(assets, childAsset(
				connection.LoadBalancerPlatform(),
				c.NewLoadBalancerIdentifier(idStr),
				"Hetzner Load Balancer "+lb.Name,
				connection.OptionLoadBalancer, idStr,
			))
		}
	}

	return &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: assets}}, nil
}

// childConfig clones the connected asset's config for a discovered child asset,
// stamping the child's discriminating option. Config.Clone leaves Options nil
// when the source config had no options (an inventory-file or env-token asset
// that omits them), so guard before writing to avoid a nil-map assignment panic.
func childConfig(conf *inventory.Config, parentID uint32, optKey, optVal string) *inventory.Config {
	cfg := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(parentID))
	if cfg.Options == nil {
		cfg.Options = map[string]string{}
	}
	cfg.Options[optKey] = optVal
	return cfg
}

// resolveDiscoveryTargets expands the "auto"/"all" aliases into the full
// set of child-asset types the provider can split a project into.
func resolveDiscoveryTargets(targets []string) []string {
	if stringx.Contains(targets, connection.DiscoveryAll) || stringx.Contains(targets, connection.DiscoveryAuto) {
		return []string{
			connection.DiscoveryFirewalls,
			connection.DiscoveryLoadBalancers,
		}
	}
	return targets
}

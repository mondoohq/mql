// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strconv"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// Discovery targets. "auto" and "all" both expand to every specific
// child-asset type the provider can split a project into.
const (
	DiscoveryAuto          = "auto"
	DiscoveryAll           = "all"
	DiscoveryFirewalls     = "firewalls"
	DiscoveryLoadBalancers = "loadbalancers"
)

// Connection options that scope a connection to a single discovered
// sub-asset. When set, the connection represents that specific resource
// (not the whole project), and the matching singular MQL resource
// (e.g. hetzner.firewall) binds to it. The value is the resource's
// numeric id as a string.
const (
	OptionFirewall     = "firewall"
	OptionLoadBalancer = "loadbalancer"
)

func childPlatform(name, segment string) *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"cloud", "hetzner", segment},
	}
	PlatformByName(name).Apply(p)
	return p
}

// FirewallPlatform is a single Hetzner Cloud firewall.
func FirewallPlatform() *inventory.Platform {
	return childPlatform("hetzner-firewall", "firewall")
}

// LoadBalancerPlatform is a single Hetzner Cloud load balancer.
func LoadBalancerPlatform() *inventory.Platform {
	return childPlatform("hetzner-loadbalancer", "loadbalancer")
}

// NewFirewallIdentifier builds the platform id for a firewall, anchored
// on the project identifier so it stays stable and unique per project.
func (c *HetznerConnection) NewFirewallIdentifier(id string) string {
	return c.Identifier() + "/firewall/" + id
}

// NewLoadBalancerIdentifier builds the platform id for a load balancer,
// anchored on the project identifier.
func (c *HetznerConnection) NewLoadBalancerIdentifier(id string) string {
	return c.Identifier() + "/loadbalancer/" + id
}

// SubAssetPlatform reports the specific platform, platform id, and asset
// name when this connection is scoped to a single discovered sub-asset.
// It returns (nil, "", "") for a plain project connection.
func (c *HetznerConnection) SubAssetPlatform() (*inventory.Platform, string, string) {
	opts := c.Conf.Options
	if id := opts[OptionFirewall]; id != "" {
		return FirewallPlatform(), c.NewFirewallIdentifier(id), "Hetzner Firewall " + id
	}
	if id := opts[OptionLoadBalancer]; id != "" {
		return LoadBalancerPlatform(), c.NewLoadBalancerIdentifier(id), "Hetzner Load Balancer " + id
	}
	return nil, "", ""
}

// AssetID parses the numeric resource id stored under the given option
// key. Returns (0, false) when the option is unset or not an integer.
func AssetID(conf *inventory.Config, key string) (int64, bool) {
	if conf == nil {
		return 0, false
	}
	s := conf.Options[key]
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// Discovery targets. "auto" and "all" both expand to every child-asset type.
const (
	DiscoveryAuto           = "auto"
	DiscoveryAll            = "all"
	DiscoveryInstances      = "instances"
	DiscoverySecurityGroups = "security-groups"
	DiscoverySksClusters    = "sks-clusters"
	DiscoveryNlbs           = "nlbs"
	DiscoveryDbaasServices  = "dbaas-services"
)

// Connection options that scope a connection to a single discovered child
// asset. The matching singular resource (exoscale.compute.instance, ...)
// binds to it. The value is the resource id, or for a DBaaS service its name.
const (
	OptionInstance      = "instance"
	OptionSecurityGroup = "security-group"
	OptionSksCluster    = "sks-cluster"
	OptionNlb           = "nlb"
	OptionDbaasService  = "dbaas-service"
	// OptionZone accompanies a zonal child asset.
	OptionZone = "zone"
)

// SubAsset describes one kind of discovered child asset.
type SubAsset struct {
	Option   string
	Platform string
	Segment  string
	Title    string
}

var SubAssets = []SubAsset{
	{Option: OptionInstance, Platform: "exoscale-compute-instance", Segment: "instance", Title: "Exoscale Instance"},
	{Option: OptionSecurityGroup, Platform: "exoscale-security-group", Segment: "security-group", Title: "Exoscale Security Group"},
	{Option: OptionSksCluster, Platform: "exoscale-sks-cluster", Segment: "sks-cluster", Title: "Exoscale SKS Cluster"},
	{Option: OptionNlb, Platform: "exoscale-nlb", Segment: "nlb", Title: "Exoscale NLB"},
	{Option: OptionDbaasService, Platform: "exoscale-dbaas-service", Segment: "dbaas-service", Title: "Exoscale DBaaS Service"},
}

// Platform builds the inventory platform for the child asset kind.
func (s SubAsset) NewPlatform() *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"cloud", "exoscale", s.Segment},
	}
	PlatformByName(s.Platform).Apply(p)
	return p
}

// Identifier builds the platform id of a child asset, anchored on the
// organization so it stays unique across organizations. Zonal resources
// whose key is only unique within a zone (DBaaS names) pass the zone.
func (c *ExoscaleConnection) SubAssetIdentifier(s SubAsset, zone, id string) string {
	if zone != "" {
		return c.Identifier() + "/" + s.Segment + "/" + zone + "/" + id
	}
	return c.Identifier() + "/" + s.Segment + "/" + id
}

// SubAsset reports the child asset this connection is scoped to, if any.
func (c *ExoscaleConnection) SubAsset() (SubAsset, string, bool) {
	for _, s := range SubAssets {
		if v := c.Conf.Options[s.Option]; v != "" {
			return s, v, true
		}
	}
	return SubAsset{}, "", false
}

// AssetOption returns a connection option, or "" when unset.
func AssetOption(conf *inventory.Config, key string) string {
	if conf == nil || conf.Options == nil {
		return ""
	}
	return conf.Options[key]
}

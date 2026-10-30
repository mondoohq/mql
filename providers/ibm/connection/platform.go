// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// Discovery targets. "auto" and "all" both expand to every child-asset type.
const (
	DiscoveryAuto              = "auto"
	DiscoveryAll               = "all"
	DiscoveryVpcInstances      = "vpc-instances"
	DiscoveryVpcSecurityGroups = "vpc-security-groups"
	DiscoveryPowerWorkspaces   = "power-workspaces"
)

// Connection options that scope a connection to a single discovered child
// asset. The matching singular resource binds to it. Each value is the
// resource's CRN, which is unique across regions and accounts.
const (
	OptionVpcInstance      = "vpc-instance"
	OptionVpcSecurityGroup = "vpc-security-group"
	OptionPowerWorkspace   = "power-workspace"
)

// SubAsset describes one kind of discovered child asset.
type SubAsset struct {
	Option   string
	Platform string
	Segment  string
	Title    string
}

var SubAssets = []SubAsset{
	{Option: OptionVpcInstance, Platform: "ibm-vpc-instance", Segment: "vpc-instance", Title: "IBM Cloud VPC Instance"},
	{Option: OptionVpcSecurityGroup, Platform: "ibm-vpc-security-group", Segment: "vpc-security-group", Title: "IBM Cloud Security Group"},
	{Option: OptionPowerWorkspace, Platform: "ibm-power-workspace", Segment: "power-workspace", Title: "IBM Power VS Workspace"},
}

// NewPlatform builds the inventory platform for the child asset kind.
func (s SubAsset) NewPlatform() *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"cloud", "ibm", s.Segment},
	}
	PlatformByName(s.Platform).Apply(p)
	return p
}

// SubAssetIdentifier builds the platform id of a child asset from its CRN,
// anchored on the account so it stays unique across accounts.
func (c *IbmConnection) SubAssetIdentifier(s SubAsset, crn string) string {
	return c.Identifier() + "/" + s.Segment + "/" + crn
}

// SubAsset reports the child asset this connection is scoped to, if any.
func (c *IbmConnection) SubAsset() (SubAsset, string, bool) {
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

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	DiscoveryAll   = "all"
	DiscoveryAuto  = "auto"
	DiscoveryHosts = "hosts"
)

type NmapConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset
	// Add custom connection fields here
}

func NewNmapConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*NmapConnection, error) {
	conn := &NmapConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	// initialize your connection here

	return conn, nil
}

func (c *NmapConnection) Name() string {
	return "nmap"
}

func (c *NmapConnection) Asset() *inventory.Asset {
	return c.asset
}

func nmapHostPlatform() *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"network", "nmap", "host"},
	}
	PlatformByName("nmap-host").Apply(pf)
	return pf
}

func nmapDomainPlatform() *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"network", "nmap", "domain"},
	}
	PlatformByName("nmap-domain").Apply(pf)
	return pf
}

func nmapPlatform() *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"network", "nmap", "org"},
	}
	PlatformByName("nmap-org").Apply(pf)
	return pf
}

func (c *NmapConnection) PlatformInfo() (*inventory.Platform, error) {
	conf := c.asset.Connections[0]

	if conf.Options != nil && conf.Options["search"] != "" {
		search := conf.Options["search"]
		switch search {
		case "host":
			return nmapHostPlatform(), nil
		case "domain":
			return nmapDomainPlatform(), nil
		}
	}
	return nmapPlatform(), nil
}

func (c *NmapConnection) Identifier() string {
	baseId := "//platformid.api.mondoo.app/runtime/nmap"

	conf := c.asset.Connections[0]
	if conf.Options != nil && conf.Options["search"] != "" {
		search := conf.Options["search"]
		switch search {
		case "host":
			return baseId + "/host/" + strings.ToLower(conf.Host)
		case "domain":
			return baseId + "/domain/" + strings.ToLower(conf.Host)
		}
	}

	return baseId
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ipinfo/provider"
)

var Config = plugin.Provider{
	Name: "ipinfo",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "ipinfo",
	ID:      "go.mondoo.com/mql/providers/ipinfo",
	Version: "13.0.29",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.29"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       provider.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "ipinfo",
			Use:   "ipinfo",
			Short: "Query ipinfo.io for IP address information",
			Long: `Use the ipinfo provider to query IP address information from ipinfo.io, including the IP address, hostname, and whether the IP address is a bogon.

Examples:
  cnspec shell ipinfo
  cnspec run ipinfo -c "ipinfo(ip('8.8.8.8')){*}"
  cnspec run ipinfo -c "ipinfo(){*}"  # Query your public IP"
  cnspec run -c "network.interfaces.map(ips.map(_.ip)).flat.map(ipinfo(_){*})"

Notes:
  - Pass an IP address to query information about that specific IP: ipinfo(ip("1.1.1.1"))
  - Pass no arguments (empty IP) to query your machine's public IP: ipinfo()
  - The bogon field indicates whether the returned IP is a private, link-local, or otherwise non-routable address. When bogon is true, the returned IP is the same as the requested IP.
  - Set IPINFO_TOKEN environment variable to use the authenticated ipinfo.io API.
`,
			Discovery: []string{},
			Flags:     []plugin.Flag{},
		},
	},
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/hetzner/connection"
	"go.mondoo.com/mql/providers/hetzner/provider"
)

var Config = plugin.Provider{
	Name: "hetzner",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "hetzner",
	ID:      "go.mondoo.com/mql/providers/hetzner",
	Version: "13.7.8",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.7.8"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "hetzner",
			Use:   "hetzner",
			Short: "a Hetzner Cloud project",
			Long: fmt.Sprintf(`
Use the hetzner provider to query servers, volumes, networks, load balancers,
and other resources in a Hetzner Cloud project.

Authenticate with a Hetzner Cloud API token:

  cnspec shell hetzner --token <api-token>

You can also pass the token via the %s environment variable.
`, connection.HCLOUD_TOKEN_VAR),
			MinArgs: 0,
			MaxArgs: 0,
			Discovery: []string{
				connection.DiscoveryAuto,
				connection.DiscoveryAll,
				connection.DiscoveryFirewalls,
				connection.DiscoveryLoadBalancers,
			},
			Flags: []plugin.Flag{
				{
					Long:    connection.OPTION_TOKEN,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Hetzner Cloud API token (env: HCLOUD_TOKEN)",
				},
				{
					Long:    connection.OPTION_ENDPOINT,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Override the Hetzner Cloud API endpoint (env: HCLOUD_ENDPOINT)",
				},
			},
		},
	},
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/network/connection"
	"go.mondoo.com/mql/providers/network/provider"
)

var Config = plugin.Provider{
	Name: "network",
	// The host this provider connects to (ADR 031).
	Root:    "network.host",
	ID:      "go.mondoo.com/mql/providers/network",
	Version: "13.3.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.3.1"},
	},
	ConnectionTypes: []string{provider.HostConnectionType},
	Platforms:       provider.Platforms,
	// Host scans are almost entirely spent waiting on DNS, TLS and HTTP against
	// unrelated targets, with no shared rate limit to trip, so this is the
	// highest default we hand out.
	DefaultParallelism: 10,
	Connectors: []plugin.Connector{
		{
			Name:  "host",
			Use:   "host HOST",
			Short: "a remote HTTP or HTTPS host",
			Long: `Use the host provider to query remote HTTP or HTTPS hosts. 

Examples:
  cnspec shell host <YOUR-DOMAIN-OR-IP>
  cnspec scan host <YOUR-DOMAIN-OR-IP>

Note:
  If you don't provide a protocol, Mondoo assumes HTTPS.
`,
			MinArgs:   1,
			MaxArgs:   1,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "insecure",
					Type:    plugin.FlagType_Bool,
					Default: "",
					Desc:    "Disable TLS/SSL verification",
				},
				{
					Long:    connection.OPTION_FOLLOW_REDIRECTS,
					Type:    plugin.FlagType_Bool,
					Default: "",
					Desc:    "Follow HTTP redirects",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=network", "category=host"},
		},
	},
}

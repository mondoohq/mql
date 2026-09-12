// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/arista/provider"
)

var Config = plugin.Provider{
	Name: "arista",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "arista.eos",
	ID:      "go.mondoo.com/mql/providers/arista",
	Version: "13.3.16",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.3.16"},
	},
	ConnectionTypes: []string{provider.ConnectionType},
	Platforms:       provider.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "arista",
			Use:   "arista user@host",
			Short: "an Arista EOS device",
			Long: `Use the arista provider to query resources on an Arista EOS network device, including system information, interfaces, and configuration.

Examples:
  cnspec shell arista <user@host>
  cnspec scan arista <user@host> --ask-pass
`,
			Discovery: []string{},
			MinArgs:   1,
			MaxArgs:   1,
			Flags: []plugin.Flag{
				{
					Long:        "ask-pass",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Prompt for connection password",
					ConfigEntry: "-",
				},
				{
					Long:        "password",
					Short:       "p",
					Type:        plugin.FlagType_String,
					Default:     "",
					Desc:        "Set the connection password",
					Option:      plugin.FlagOption_Password,
					ConfigEntry: "-",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=network", "category=arista"},
		},
	},
}

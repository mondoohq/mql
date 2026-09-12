// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ipmi/provider"
)

var Config = plugin.Provider{
	Name: "ipmi",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "ipmi",
	ID:      "go.mondoo.com/mql/providers/ipmi",
	Version: "13.0.29",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.29"},
	},
	ConnectionTypes: []string{provider.ConnectionType},
	Platforms:       provider.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "ipmi",
			Use:   "ipmi USER@HOST",
			Short: "an IPMI interface",
			Long: `Use the ipmi provider to query resources using the Intelligent Platform Management Interface (IPMI).

IPMI provides management and monitoring capabilities independently of the host system's CPU,
firmware (BIOS or UEFI), and operating system.

Examples:
  cnspec shell ipmi <user@host>
	cnspec scan ipmi <user@host>
`,
			MinArgs:   1,
			MaxArgs:   1,
			Discovery: []string{},
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
					Desc:        "Set the connection password for IPMI connection",
					Option:      plugin.FlagOption_Password,
					ConfigEntry: "-",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=network", "category=ipmi"},
		},
	},
}

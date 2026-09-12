// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vsphere/connection"
	"go.mondoo.com/mql/providers/vsphere/provider"
	"go.mondoo.com/mql/providers/vsphere/resources"
)

var Config = plugin.Provider{
	Name: "vsphere",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "vsphere",
	ID:      "go.mondoo.com/mql/providers/vsphere",
	Version: "13.7.8",
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.7.8"},
	},
	ConnectionTypes: []string{provider.ConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "vsphere",
			Use:   "vsphere user@host",
			Short: "a VMware vSphere installation",
			Long: `Use the vsphere provider to query VMware vSphere installations. 

Examples:
  cnspec scan vsphere <USER>@<HOST> --askpass
	cnspec shell vsphere <USER>@<HOST> --password <YOUR-PASSWORD>
`,
			Discovery: []string{
				resources.DiscoveryApi,
				resources.DiscoveryInstances,
				resources.DiscoveryHostMachines,
			},
			MinArgs: 1,
			MaxArgs: 1,
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
			PathSegments: []string{"technology=vmware"},
			Key:          "platform",
			Title:        "Platform",
			Values: map[string]*inventory.AssetUrlBranch{
				// redhat, arch, ...
				"*": {
					Key:   "version",
					Title: "Version",
					Values: map[string]*inventory.AssetUrlBranch{
						// any valid version for the OS
						"*": nil,
					},
				},
			},
		},
	},
}

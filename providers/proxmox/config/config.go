// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

var Config = plugin.Provider{
	Name: "proxmox",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "proxmox",
	ID:      "go.mondoo.com/mql/providers/proxmox",
	Version: "0.5.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "0.5.1"},
	},
	Platforms:       connection.Platforms,
	ConnectionTypes: []string{"proxmox"},
	Connectors: []plugin.Connector{
		{
			Name:  "proxmox",
			Use:   "proxmox --host HOST --token TOKEN [flags]",
			Short: "a Proxmox VE hypervisor",
			Long: `Use the proxmox provider to query and scan Proxmox VE clusters.

Examples:
  cnspec scan proxmox --host https://192.168.1.10:8006 --token 'PVEAPIToken=user@realm!id=secret'
  cnspec scan proxmox --host https://pve.example.com:8006 --token 'PVEAPIToken=user@realm!id=secret' --insecure
`,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long: "host",
					Type: plugin.FlagType_String,
					Desc: "Proxmox VE host URL (e.g. https://192.168.1.10:8006)",
				},
				{
					Long:  "token",
					Short: "t",
					Type:  plugin.FlagType_String,
					Desc:  "Proxmox API token (format: PVEAPIToken=user@realm!tokenid=secret)",
				},
				{
					Long:        "insecure",
					Short:       "k",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Skip TLS certificate verification",
					ConfigEntry: "-",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=virtualization", "provider=proxmox"},
			Key:          "kind",
			Title:        "Proxmox VE Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"cluster": {
					Key:   "host",
					Title: "Proxmox VE Host",
				},
			},
		},
	},
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mikrotik/provider"
)

var Config = plugin.Provider{
	Name: "mikrotik",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "mikrotik",
	ID:      "go.mondoo.com/mql/providers/mikrotik",
	Version: "13.0.11",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.11"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       provider.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:    "mikrotik",
			Use:     "mikrotik user@host [flags]",
			Short:   "a MikroTik RouterOS device",
			MinArgs: 1,
			MaxArgs: 1,
			Long: `Use the mikrotik provider to query MikroTik RouterOS devices through the
RouterOS API.

Examples:
  cnspec scan mikrotik admin@192.168.88.1 --password 'secret'
  cnspec scan mikrotik admin@192.168.88.1 --tls --ask-pass
  cnspec shell mikrotik admin@router.example.com --port 8728 --password 'secret'
`,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "password",
					Short:   "p",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Password for the RouterOS user",
				},
				{
					Long:        "ask-pass",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Prompt for the connection password",
					ConfigEntry: "-",
				},
				{
					Long:    "port",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "RouterOS API port (default 8728, or 8729 with --tls)",
				},
				{
					Long:        "tls",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Connect using the RouterOS API-SSL service",
					ConfigEntry: "-",
				},
				{
					Long:        "insecure",
					Short:       "k",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Skip TLS certificate verification (used with --tls)",
					ConfigEntry: "-",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=network", "category=mikrotik"},
			Key:          "kind",
			Title:        "MikroTik Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"device": {
					Key:   "host",
					Title: "MikroTik Host",
				},
			},
		},
	},
}

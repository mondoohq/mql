// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/talos/connection"
	"go.mondoo.com/mql/providers/talos/provider"
)

var Config = plugin.Provider{
	Name: "talos",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "talos",
	ID:      "go.mondoo.com/mql/providers/talos",
	Version: "14.0.0",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.0"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:    "talos",
			Use:     "talos [node]",
			Short:   "a Talos Linux node",
			MaxArgs: 1,
			Long: `Use the talos provider to query a Talos Linux node through the Talos API.

The provider authenticates with a talosconfig, as talosctl does: the file
given with --talosconfig, else TALOSCONFIG, else ~/.talos/config. It reads the
node's version, kernel parameters and the resources the Talos API serves. A
talosconfig with the os:reader role reads everything that isn't sensitive.
The Talos API serves the rest only to the os:admin role: the machine
configuration, the other sensitive resources, and the kernel parameters
Talos doesn't manage, which the provider reads from /proc/sys. The machine
configuration is returned with its secrets removed.

Examples:
  cnspec shell talos 10.5.0.2 --talosconfig ./talosconfig
  cnspec scan talos --context prod --endpoints 192.0.2.10 --node 192.0.2.21
`,
			Flags: []plugin.Flag{
				{
					Long:    connection.OptionTalosconfig,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to the talosconfig file (default TALOSCONFIG, else ~/.talos/config)",
				},
				{
					Long:    connection.OptionContext,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "talosconfig context to use instead of the current one",
				},
				{
					Long:    connection.OptionEndpoints,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Comma-separated Talos API endpoints that replace the context's endpoints",
				},
				{
					Long:    connection.OptionNode,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Node to query through the endpoints (default the context's first node)",
				},
			},
		},
	},
}

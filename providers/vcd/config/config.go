// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vcd/provider"
)

var Config = plugin.Provider{
	Name: "vcd",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "vcd",
	ID:      "go.mondoo.com/mql/providers/vcd",
	Version: "13.0.28",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.28"},
	},
	ConnectionTypes: []string{provider.ConnectionType},
	Platforms:       provider.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "vcd",
			Use:   "vcd [--user <user>] [--host <host>] [--organization <organization>] [--ask-pass] [--password <password>]",
			Short: "a VMware Cloud Director installation",
			Long: `Use the vcd provider to query resources in a VMware Cloud Director environment. The VMware Cloud Director platform facilitates the operation and management of virtual resources within a multi-tenant cloud environment.

			Examples:
			  cnspec shell vcd --user <USER-NAME> --host <HOST-NAME> --ask-pass
				cnspec scan vcd --user <USER-NAME> --host <HOST-NAME> --password <PASSWORD>
`,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "user",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "VMware Cloud Director username for authentication",
					Option:  plugin.FlagOption_Required,
				},
				{
					Long:    "host",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "VMware Cloud Director hostname (e.g., vcd.example.com)",
					Option:  plugin.FlagOption_Required,
				},
				{
					Long:    "organization",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "VMware Cloud Director organization name to connect to",
				},
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
}

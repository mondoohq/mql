// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mondoo/provider"
)

var Config = plugin.Provider{
	Name: "mondoo",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	// A connection reports the concrete kind through ConnectRes.Root.
	Root:    "mondoo.organization",
	ID:      "go.mondoo.com/mql/providers/mondoo",
	Version: "13.1.18",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.18"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       provider.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "mondoo",
			Use:   "mondoo",
			Short: "Mondoo Platform",
			Long: `Use the mondoo provider to query resources in Mondoo Platform.

To query Mondoo Platform from a workstation, the workstation must be registered with Mondoo Platform. To learn how to register a workstation, read https://mondoo.com/docs/cnspec/install/registration. 

Examples:
  cnspec shell mondoo
	cnspec scan mondoo
`,
			MinArgs:   0,
			MaxArgs:   4,
			Discovery: []string{},
			Flags:     []plugin.Flag{},
		},
	},
}

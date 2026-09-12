// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/bicep/provider"
)

var Config = plugin.Provider{
	Name: "bicep",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "bicep",
	ID:      "go.mondoo.com/mql/providers/bicep",
	Version: "13.4.13",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.4.13"},
	},
	Maturity:        resources.MaturityExperimental,
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       provider.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "bicep",
			Use:   "bicep PATH",
			Short: "a Bicep file, directory, or ARM template JSON",
			Long: `Use the bicep provider to query Azure Bicep files and ARM templates, including resources, parameters, modules, and compiled output.

Examples:
  cnspec run bicep ./main.bicep -c "bicep.files { resources { type apiVersion } }"
  cnspec shell bicep ./infra/
`,
			MinArgs:   1,
			MaxArgs:   1,
			Discovery: []string{},
			Flags:     []plugin.Flag{},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=iac", "category=bicep"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"template": nil,
			},
		},
	},
}

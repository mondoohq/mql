// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudformation/provider"
)

var Config = plugin.Provider{
	Name: "cloudformation",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "cloudformation.template",
	ID:      "go.mondoo.com/mql/providers/cloudformation",
	Version: "14.0.0",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.0"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       provider.Platforms,
	// PerFile: the connection reads exactly one document, so the unit offered
	// has to be the file rather than the folder it sits in.
	Targets: []plugin.TargetOptIn{
		{
			Target: "iac", Discovery: "cloudformation", ConnType: provider.DefaultConnectionType,
			Auto: true, PerFile: true,
			Match: []plugin.Matcher{
				{Glob: "*.yaml"}, {Glob: "*.yml"}, {Glob: "*.json"}, {Glob: "*.template"},
			},
		},
	},
	Connectors: []plugin.Connector{
		{
			Name:  "cloudformation",
			Use:   "cloudformation PATH",
			Short: "an AWS CloudFormation template or AWS SAM template",
			Long: `Use the cloudformation provider to query AWS CloudFormation templates or AWS SAM templates, including resources, parameters, outputs, and mappings.

Examples:
  cnspec shell cloudformation <path>
  cnspec scan cloudformation <path>
`,
			MinArgs:   1,
			MaxArgs:   1,
			Discovery: []string{},
			Flags:     []plugin.Flag{},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=iac", "category=cloudformation"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"template": nil,
			},
		},
	},
}

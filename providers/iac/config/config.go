// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/iac/connection"
)

var Config = plugin.Provider{
	Name: "iac",
	// The tree this connection reached, and what was found in it (ADR 031).
	Root: "iac",
	ID:   "go.mondoo.com/mql/providers/iac",
	// A builtin ships with the binary rather than through the registry, so it
	// tracks the binary's version the way core does.
	Version: mql.GetVersion(),
	// Every root carries `asset`, which core owns (ADR 042). Nothing else:
	// iac emits assets, it never calls another provider's resources, and
	// Requires entries are installed eagerly -- declaring the IaC providers
	// here would install all of them on first use whatever the directory holds
	// (ADR 045).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.0"},
	},
	Maturity:        resources.MaturityExperimental,
	ConnectionTypes: []string{connection.ConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "iac",
			Use:   "iac PATH",
			Short: "a tree of infrastructure-as-code files",
			Long: `Use the iac provider to scan a directory for infrastructure as code and hand each entry point to the tool that owns it: Terraform, OpenTofu, Ansible, CloudFormation, Bicep, Helm, Kustomize, Kubernetes manifests and Dockerfiles.

Examples:
  mql shell iac ./repo -c "iac.detections { tool path }"
  cnspec scan iac ./repo
  cnspec scan iac ./repo --discover terraform,helm
`,
			MinArgs: 1,
			MaxArgs: 1,
			// Deliberately empty: --discover values here are the names the
			// enumerated target opt-ins declare, so the help text is built from
			// what this machine can actually reach (ADR 045).
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long: "iac-ignore",
					Type: plugin.FlagType_List,
					Desc: "Directory names to skip while walking the tree, replacing the defaults (" +
						".git, .terraform, .terragrunt-cache, .venv, node_modules, vendor, target, dist).",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=iac", "category=project"},
			Key:          "source",
			Title:        "Source",
			Values: map[string]*inventory.AssetUrlBranch{
				connection.KindFile: nil,
			},
		},
	},
}

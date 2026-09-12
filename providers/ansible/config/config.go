// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ansible/provider"
)

var Config = plugin.Provider{
	Name: "ansible",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "ansible",
	ID:      "go.mondoo.com/mql/providers/ansible",
	Version: "13.2.16",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.2.16"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       provider.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "ansible",
			Use:   "ansible PATH",
			Short: "an Ansible playbook or project",
			Long: `Use the ansible provider to statically analyze Ansible infrastructure as code.

Point PATH at a single playbook file to query its plays, tasks, handlers, and
variables. Point PATH at a project directory to additionally query roles,
inventory and host/group variables, Galaxy requirements, ansible.cfg, and
vault-encrypted files.

Examples:
  cnspec shell ansible <playbook.yml>
  cnspec shell ansible <project-dir>
  cnspec scan ansible <project-dir>
`,
			MinArgs:   1,
			MaxArgs:   1,
			Discovery: []string{},
			Flags:     []plugin.Flag{},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=iac", "category=ansible"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"playbook": nil,
				"project":  nil,
			},
		},
	},
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/terraform/provider"
)

var Config = plugin.Provider{
	Name: "terraform",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "terraform",
	ID:      "go.mondoo.com/mql/providers/terraform",
	Version: "13.3.14",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.3.14"},
	},
	Platforms: provider.Platforms,
	ConnectionTypes: []string{
		provider.StateConnectionType,
		provider.PlanConnectionType,
		provider.HclConnectionType,
		provider.HclGitConnectionType,
	},
	Connectors: []plugin.Connector{
		{
			Name:  "terraform",
			Use:   "terraform PATH",
			Short: "Terraform HCL configurations, plan files, and state files",
			Long: `Use the terraform connector to query Terraform HCL, plan, or state files as well as directories of files.

A directory is read the way Terraform itself reads it: the .tf, .tf.json,
.tfvars and .tfvars.json files. Any .tofu-flavored file sitting next to them is
skipped, because Terraform never applies it. Use the opentofu connector for
those.

Available commands:
  plan                       Terraform plan file
  state                      Terraform state file

Examples:
  cnspec shell terraform <PATH-TO-HCL-DIRECTORY>
  cnspec scan terraform <PATH-TO-HCL-FILE>
  cnspec scan terraform plan <PATH-TO-PLAN-JSON>
  cnspec scan terraform state <PATH-TO-STATE-JSON>
`,
			MinArgs:   1,
			MaxArgs:   2,
			Discovery: []string{},
			Flags:     iacFlags(),
		},
		{
			Name:    "opentofu",
			Aliases: []string{"tofu"},
			Use:     "opentofu PATH",
			Short:   "OpenTofu HCL configurations, plan files, and state files",
			Long: `Use the opentofu connector to query OpenTofu HCL, plan, or state files as well as directories of files.

A directory is read the way OpenTofu itself reads it. Where a .tofu-flavored
file shares a name with its Terraform equivalent, the .tofu file wins and the
.tf file is not read: main.tofu replaces main.tf, and .tofu.json, .tofuvars and
.tofuvars.json replace their .tf equivalents in the same way. Files with no
.tofu counterpart are read as they are, so a configuration that has not been
renamed is queried unchanged.

Plan and state files carry no marker of their own -- their JSON is identical
between the two tools -- so the connector is what says which tool produced them.
It selects the platform the asset is reported under; the file is read the same
way either way.

Available commands:
  plan                       OpenTofu plan file
  state                      OpenTofu state file

Examples:
  cnspec shell opentofu <PATH-TO-HCL-DIRECTORY>
  cnspec scan opentofu <PATH-TO-HCL-FILE>
  cnspec scan opentofu plan <PATH-TO-PLAN-JSON>
  cnspec scan opentofu state <PATH-TO-STATE-JSON>
`,
			MinArgs:   1,
			MaxArgs:   2,
			Discovery: []string{},
			Flags:     iacFlags(),
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=iac", "category=terraform"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"hcl":   nil,
				"plan":  nil,
				"state": nil,
			},
		},
	},
}

// iacFlags are the flags both connectors carry. They read the same kinds of
// file from the same kinds of directory, so a flag that applies to one applies
// to the other; the connector chooses the tool, not the feature set. A fresh
// slice per connector, so the CLI appending its built-in flags to one cannot
// reach the other.
func iacFlags() []plugin.Flag {
	return []plugin.Flag{
		{
			Long:    "ignore-dot-terraform",
			Type:    plugin.FlagType_Bool,
			Default: "false",
			Desc:    "Exclude the .terraform directory (contains cached provider plugins and modules)",
			// "-" reads the flag straight from the command line, which is what
			// every other provider does. A named config entry is bound into
			// viper under that name but read back under the flag's own name, so
			// the value the user typed never arrived: this flag was accepted and
			// then silently ignored, and .terraform was always scanned.
			ConfigEntry: "-",
		},
	}
}

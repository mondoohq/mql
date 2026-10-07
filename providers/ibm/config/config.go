// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ibm/connection"
	"go.mondoo.com/mql/providers/ibm/provider"
)

var Config = plugin.Provider{
	Name: "ibm",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "ibm",
	ID:      "go.mondoo.com/mql/providers/ibm",
	Version: "14.0.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.0"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "ibm",
			Use:   "ibm",
			Short: "an IBM Cloud account",
			Long: fmt.Sprintf(`
Use the ibm provider to query IAM, resource groups and instances, VPC
infrastructure, and Power Virtual Server workspaces in an IBM Cloud account.

Authenticate with an IBM Cloud API key:

  cnspec shell ibm --api-key <key>
  cnspec shell ibm --api-key-file apikey.json

You can also set the %s environment variable.
Restrict the VPC regions queried with --regions us-south,eu-de, and narrow
discovered resources by tag with --filters tags=env:prod.
`, connection.APIKeyEnvVar),
			MinArgs: 0,
			MaxArgs: 0,
			Discovery: []string{
				connection.DiscoveryAuto,
				connection.DiscoveryAll,
				connection.DiscoveryVpcInstances,
				connection.DiscoveryVpcSecurityGroups,
				connection.DiscoveryPowerWorkspaces,
			},
			Flags: []plugin.Flag{
				{
					Long:    "api-key",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "IBM Cloud API key (env: IBMCLOUD_API_KEY)",
				},
				{
					Long:    connection.OptionAPIKeyFile,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to an IBM Cloud API key JSON file, as downloaded from the console or written by ibmcloud iam api-key-create --file",
				},
				{
					Long: connection.OptionRegions,
					Type: plugin.FlagType_List,
					Desc: "Restrict the VPC regions queried, for example us-south,eu-de (env: IBMCLOUD_REGIONS)",
				},
				{
					Long:    "filters",
					Type:    plugin.FlagType_KeyValue,
					Default: "",
					Desc:    "Filter discovered resources by tag, e.g., --filters tags=env:prod,team --filters exclude:tags=env:dev",
				},
			},
		},
	},
}

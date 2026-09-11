// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/hcp/connection"
	"go.mondoo.com/mql/providers/hcp/provider"
)

var Config = plugin.Provider{
	Name: "hcp",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "hcp",
	ID:      "go.mondoo.com/mql/providers/hcp",
	Version: "13.0.6",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.6"},
	},
	Platforms: connection.Platforms,
	ConnectionTypes: []string{
		provider.DefaultConnectionType,
	},
	Connectors: []plugin.Connector{
		{
			Name:  "hcp",
			Use:   "hcp",
			Short: "a HashiCorp Cloud Platform organization",
			Long: `Use the hcp provider to query the security posture of a HashiCorp Cloud
Platform (HCP) organization and the products provisioned beneath it.

Connecting to an organization discovers every project and, within each
project, the Vault, Consul, and Boundary clusters, the Packer registry, and
the Waypoint applications as child assets. Scope the connection to a single
project with --project-id.

Authenticate with an HCP service principal (client id and client secret).

Examples:
  cnspec shell hcp --client-id <id> --client-secret <secret>
  cnspec shell hcp --org-id <org-id> --client-id <id> --client-secret <secret>
  cnspec shell hcp --project-id <project-id> --client-id <id> --client-secret <secret>

Notes:
  Set HCP_CLIENT_ID, HCP_CLIENT_SECRET, HCP_ORGANIZATION_ID, or
  HCP_PROJECT_ID to omit the matching flags.
`,
			Discovery: []string{
				connection.DiscoveryAuto,
				connection.DiscoveryAll,
				connection.DiscoveryProjects,
				connection.DiscoveryVaultClusters,
				connection.DiscoveryConsulClusters,
				connection.DiscoveryBoundaryClusters,
				connection.DiscoveryPackerRegistries,
				connection.DiscoveryWaypointApplications,
			},
			Flags: []plugin.Flag{
				{
					Long:    "client-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "HCP service principal client id",
				},
				{
					Long:    "client-secret",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "HCP service principal client secret",
				},
				{
					Long:    "org-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "HCP organization id (defaults to the service principal's organization)",
				},
				{
					Long:    "project-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "HCP project id for a single-project connect",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=hcp"},
			Key:          "organization",
			Title:        "Organization",
			Values: map[string]*inventory.AssetUrlBranch{
				"*": {
					Key:   "project",
					Title: "Project",
					Values: map[string]*inventory.AssetUrlBranch{
						"*": {
							Key:   "resource",
							Title: "Resource",
							Values: map[string]*inventory.AssetUrlBranch{
								"*": nil,
							},
						},
					},
				},
			},
		},
	},
}

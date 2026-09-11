// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mongodbatlas/connection"
	"go.mondoo.com/mql/providers/mongodbatlas/provider"
)

var Config = plugin.Provider{
	Name: "mongodbatlas",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "mongodbatlas",
	ID:      "go.mondoo.com/mql/providers/mongodbatlas",
	Version: "13.4.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.4.1"},
	},
	Platforms: connection.Platforms,
	ConnectionTypes: []string{
		provider.DefaultConnectionType,
	},
	Connectors: []plugin.Connector{
		{
			Name:  "mongodbatlas",
			Use:   "mongodbatlas",
			Short: "a MongoDB Atlas organization or project",
			Long: `Use the mongodbatlas provider to query the security posture of a MongoDB Atlas
organization and its projects.

Connecting to an organization discovers every project as a child asset. You can
also scope the connection to a single project with --project-id.

Authenticate with a programmatic API key (public/private) or a service account
(client id/secret).

Examples:
  cnspec shell mongodbatlas --org-id <org-id> --public-key <public> --private-key <private>
  cnspec shell mongodbatlas --project-id <project-id> --client-id <id> --client-secret <secret>

Notes:
  Set MONGODB_ATLAS_ORG_ID, MONGODB_ATLAS_PUBLIC_KEY, MONGODB_ATLAS_PRIVATE_KEY,
  MONGODB_ATLAS_CLIENT_ID, or MONGODB_ATLAS_CLIENT_SECRET to omit the matching
  flags.
`,
			Discovery: []string{
				connection.DiscoveryAuto,
				connection.DiscoveryAll,
				connection.DiscoveryProjects,
			},
			Flags: []plugin.Flag{
				{
					Long:    "org-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "MongoDB Atlas organization id (connects to the org and discovers projects)",
				},
				{
					Long:    "project-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "MongoDB Atlas project id for a single-project connect",
				},
				{
					Long:    "public-key",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Programmatic API key public key",
				},
				{
					Long:    "private-key",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Programmatic API key private key",
				},
				{
					Long:    "client-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Service account OAuth client id",
				},
				{
					Long:    "client-secret",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Service account OAuth client secret",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=atlas"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"org": {
					PathSegments: []string{"kind=org"},
					Key:          "org",
					Title:        "Organization",
					Values: map[string]*inventory.AssetUrlBranch{
						"*": {
							Key:   "project",
							Title: "Project",
							Values: map[string]*inventory.AssetUrlBranch{
								"*": nil,
							},
						},
					},
				},
				"project": {
					PathSegments: []string{"kind=project"},
					Key:          "project",
					Title:        "Project",
					Values: map[string]*inventory.AssetUrlBranch{
						"*": nil,
					},
				},
			},
		},
	},
}

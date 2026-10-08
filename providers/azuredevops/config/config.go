// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azuredevops/connection"
	"go.mondoo.com/mql/providers/azuredevops/provider"
)

var Config = plugin.Provider{
	Name: "azuredevops",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	// A connection reports the concrete kind through ConnectRes.Root.
	Root: "azuredevops",
	ID:   "go.mondoo.com/mql/providers/azuredevops",
	// A pre-release: it is published to the preview channel until a first
	// customer scan has proven it.
	Version: "14.0.0",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.0"},
	},
	ConnectionTypes: []string{provider.ConnectionType},
	// Azure DevOps throttles by cost per user, and a scan walks every project
	// and repository, so this stays deliberately low.
	DefaultParallelism: 4,
	Connectors: []plugin.Connector{
		{
			Name:  "azuredevops",
			Use:   "azuredevops",
			Short: "an Azure DevOps organization or repository",
			Long: `Use the azuredevops provider to query an Azure DevOps Services organization and its Git repositories.

Available commands:
  org                       Azure DevOps organization
  repo                      Azure DevOps repository

Examples:
  mql discover azuredevops org <ORG_NAME> --token <PAT>
  mql discover azuredevops org <ORG_NAME> --tenant-id <TENANT_ID> --client-id <CLIENT_ID> --client-secret <SECRET>
  mql discover azuredevops org <ORG_NAME> --token <PAT> --repos "<PROJECT>/*" --repos-exclude "<PROJECT>/<REPO>"
  mql discover azuredevops org <ORG_NAME> --token <PAT> --discover repos,terraform
  mql run azuredevops org <ORG_NAME> --token <PAT> -c "azuredevops.organization.projects { name }"
  mql shell azuredevops org <ORG_NAME> --token <PAT> --discover organization
  mql shell azuredevops repo <ORG_NAME>/<PROJECT>/<REPO> --token <PAT>

Notes:
  Only Azure DevOps Services (dev.azure.com) is supported, not Azure DevOps Server.

  Authenticate with a personal access token, passed with --token or set in the AZURE_DEVOPS_TOKEN environment variable, or with a Microsoft Entra service principal. For the service principal, pass --tenant-id and --client-id and give the client secret with --client-secret or the AZURE_CLIENT_SECRET environment variable. Add the service principal to the organization (Organization settings, Users) before scanning.

  A project whose repositories the credential cannot list is skipped and reported. Discovery fails when the credential sees no project or can read none: add the service principal to the projects to scan, not only to the organization. Azure DevOps hides the projects a credential has no access to, so they are not reported.

  Repository filters match "<PROJECT>/<REPO>". The star does not cross the slash.
`,
			MinArgs: 2,
			MaxArgs: 2,
			Discovery: []string{
				connection.DiscoveryOrganization,
				connection.DiscoveryRepos,
				connection.DiscoveryTerraform,
				connection.DiscoveryK8sManifests,
			},
			Flags: []plugin.Flag{
				{
					Long:    "token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Azure DevOps personal access token (also AZURE_DEVOPS_TOKEN)",
				},
				{
					Long:    "tenant-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Microsoft Entra tenant ID of the service principal (also AZURE_TENANT_ID)",
				},
				{
					Long:    "client-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Microsoft Entra client ID of the service principal (also AZURE_CLIENT_ID)",
				},
				{
					Long:    "client-secret",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Client secret of the service principal (also AZURE_CLIENT_SECRET)",
				},
				{
					Long:    "repos",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Only include repositories matching these comma-separated <project>/<repo> globs",
				},
				{
					Long:    "repos-exclude",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Filter out repositories matching these comma-separated <project>/<repo> globs",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=azuredevops"},
			Key:          "scope",
			Title:        "Scope",
			Values: map[string]*inventory.AssetUrlBranch{
				"organization": {
					Key:   "organization",
					Title: "Organization",
					Values: map[string]*inventory.AssetUrlBranch{
						"*": {
							Key:   "asset",
							Title: "Asset",
							Values: map[string]*inventory.AssetUrlBranch{
								"organization": nil,
								"project": {
									Key:   "project",
									Title: "Project",
									Values: map[string]*inventory.AssetUrlBranch{
										"*": {
											Key:   "asset",
											Title: "Asset",
											Values: map[string]*inventory.AssetUrlBranch{
												"repository": nil,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	},
	Platforms: connection.Platforms,
}

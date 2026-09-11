// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/stackit/connection"
	"go.mondoo.com/mql/providers/stackit/provider"
	"go.mondoo.com/mql/providers/stackit/resources"
)

var Config = plugin.Provider{
	Name: "stackit",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "stackit",
	ID:      "go.mondoo.com/mql/providers/stackit",
	Version: "13.7.2",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.7.2"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "stackit",
			Use:   "stackit",
			Short: "a STACKIT project",
			Long: fmt.Sprintf(`
Use the stackit provider to query servers, networks, Kubernetes clusters,
managed databases, object storage, and other STACKIT cloud resources scoped
to a single project.

Authenticate with a STACKIT service account key file:

  cnspec shell stackit --project-id <uuid> --service-account-key-path /path/to/sa-key.json

You can also pass credentials via STACKIT environment variables
(%s, %s, %s, %s).
`,
				connection.ProjectIDEnvVar,
				connection.ServiceAccountKeyPathEnvVar,
				connection.ServiceAccountKeyEnvVar,
				connection.TokenEnvVar,
			),
			MinArgs: 0,
			MaxArgs: 0,
			Discovery: []string{
				resources.DiscoveryAuto,
				resources.DiscoveryAll,
				resources.DiscoveryServers,
				resources.DiscoverySkeClusters,
				resources.DiscoveryObjectStorageBuckets,
				resources.DiscoveryPostgresFlex,
				resources.DiscoveryMongoDbFlex,
				resources.DiscoverySqlServerFlex,
				resources.DiscoveryOpenSearch,
				resources.DiscoveryMariaDb,
				resources.DiscoveryRedis,
				resources.DiscoveryRabbitMq,
				resources.DiscoveryLogMe,
				resources.DiscoverySecretsManager,
			},
			Flags: []plugin.Flag{
				{
					Long:    connection.OptionProjectID,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    fmt.Sprintf("STACKIT project ID (env: %s)", connection.ProjectIDEnvVar),
				},
				{
					Long:    connection.OptionRegion,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    fmt.Sprintf("STACKIT region (env: %s, default: %s)", connection.RegionEnvVar, connection.DefaultRegion),
				},
				{
					Long:    connection.OptionEndpoint,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    fmt.Sprintf("Override the STACKIT API endpoint (env: %s)", connection.EndpointEnvVar),
				},
				{
					Long:    connection.OptionToken,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    fmt.Sprintf("STACKIT service account token (env: %s)", connection.TokenEnvVar),
				},
				{
					Long:    connection.OptionServiceAccountKey,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    fmt.Sprintf("STACKIT service account key JSON (env: %s)", connection.ServiceAccountKeyEnvVar),
				},
				{
					Long:    connection.OptionServiceAccountKeyPath,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    fmt.Sprintf("Path to a STACKIT service account key JSON (env: %s)", connection.ServiceAccountKeyPathEnvVar),
				},
				{
					Long:    connection.OptionPrivateKey,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    fmt.Sprintf("STACKIT service account RSA private key (env: %s)", connection.PrivateKeyEnvVar),
				},
				{
					Long:    connection.OptionPrivateKeyPath,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    fmt.Sprintf("Path to a STACKIT service account RSA private key (env: %s)", connection.PrivateKeyPathEnvVar),
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=stackit"},
			Key:          "project",
			Title:        "Project",
			Values: map[string]*inventory.AssetUrlBranch{
				"*": {
					Key:   "service",
					Title: "Service",
					Values: map[string]*inventory.AssetUrlBranch{
						"compute":         nil,
						"ske":             nil,
						"object-storage":  nil,
						"postgres-flex":   nil,
						"mongodb-flex":    nil,
						"sqlserver-flex":  nil,
						"opensearch":      nil,
						"mariadb":         nil,
						"redis":           nil,
						"rabbitmq":        nil,
						"logme":           nil,
						"secrets-manager": nil,
					},
				},
			},
		},
	},
}

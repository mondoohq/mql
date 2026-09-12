// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/provider"
	"go.mondoo.com/mql/providers/oci/resources"
)

var Config = plugin.Provider{
	Name: "oci",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "oci",
	ID:      "go.mondoo.com/mql/providers/oci",
	Version: "13.21.1",
	Requires: []plugin.ProviderDep{
		// Every root carries `asset`, which core owns (ADR 042).
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.21.1"},
		{ID: "go.mondoo.com/mql/providers/network", Name: "network", MinVersion: "13.21.1"},
	},
	ConnectionTypes: []string{provider.ConnectionType},
	Platforms:       resources.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "oci",
			Use:   "oci",
			Short: "an Oracle Cloud Infrastructure tenancy",
			Long: `Use the oci provider to query resources in an Oracle Cloud Infrastructure tenancy, including compute instances, networks, storage, and identity resources.

Examples:
  cnspec shell oci --tenancy <tenancy_ocid> --user <user_ocid> --region <region> --key-path <path_to_private_key> --fingerprint <key_fingerprint>
  cnspec scan oci --tenancy <tenancy_ocid> --user <user_ocid> --region <region> --key-path <path_to_private_key> --fingerprint <key_fingerprint>
  cnspec shell oci --profile MYPROFILE
  cnspec shell oci --config-file /path/to/config --profile MYPROFILE
  cnspec scan oci --auth-method instance-principal
  cnspec scan oci --auth-method workload-identity
`,
			Discovery: []string{
				resources.DiscoveryTenancy,
				resources.DiscoverySecurityLists,
				resources.DiscoveryUsers,
				resources.DiscoveryPolicies,
				resources.DiscoveryBuckets,
				resources.DiscoveryAPIGatewayDeployments,
				resources.DiscoveryLoadBalancers,
				resources.DiscoveryRedisClusters,
				resources.DiscoveryVaultSecrets,
				resources.DiscoveryOkeClusters,
				resources.DiscoveryGenerativeAiEndpoints,
			},
			Flags: []plugin.Flag{
				{
					Long:    "tenancy",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "The tenancy's OCID",
				},
				{
					Long:    "user",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "The user's OCID",
				},
				{
					Long:    "region",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "The OCI region to connect to (e.g., us-ashburn-1)",
				},
				{
					Long:    "key-path",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to the private key file for API key authentication",
				},
				{
					Long:    "fingerprint",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "The fingerprint of the private key",
				},
				{
					Long:    "key-secret",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Passphrase for the private key file, if encrypted",
				},
				{
					Long:    "profile",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "OCI config profile name (e.g., DEFAULT)",
				},
				{
					Long:    "config-file",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to OCI config file (default: ~/.oci/config)",
				},
				{
					Long:    "auth-method",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Authentication method: api-key (default), instance-principal, resource-principal, workload-identity, or security-token",
				},
				{
					Long:    "filters",
					Type:    plugin.FlagType_KeyValue,
					Default: "",
					Desc:    "Filter options, e.g., --filters regions=us-ashburn-1,us-phoenix-1 --filters compartments=production --filters exclude:compartments=sandbox --filters tag:env=prod --filters tag:Operations.CostCenter=42 --filters exclude:tag:env=dev",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=oci"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"tenancy": nil,
			},
		},
	},
}

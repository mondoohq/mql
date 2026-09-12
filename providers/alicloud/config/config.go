// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/providers/alicloud/provider"
	"go.mondoo.com/mql/providers/alicloud/resources"
)

var Config = plugin.Provider{
	Name: "alicloud",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "alicloud",
	ID:      "go.mondoo.com/mql/providers/alicloud",
	Version: "13.5.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.5.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "alicloud",
			Use:   "alicloud",
			Short: "an Alibaba Cloud account",
			Long: `Use the alicloud provider to query resources in an Alibaba Cloud account, including ECS instances, VPC networks, OSS buckets, RAM identities, and managed databases.

Credentials are read from the flags below, then from the standard Alibaba Cloud environment variables (ALIBABA_CLOUD_ACCESS_KEY_ID, ALIBABA_CLOUD_ACCESS_KEY_SECRET, ALIBABA_CLOUD_SECURITY_TOKEN), then from the shared credentials file (~/.alibabacloud/credentials), and finally from an ECS instance RAM role when running inside Alibaba Cloud.

Examples:
  cnspec shell alicloud --access-key-id <id> --access-key-secret <secret>
  cnspec scan alicloud --region cn-hangzhou
  cnspec scan alicloud --regions cn-hangzhou,ap-southeast-1
  cnspec scan alicloud --role-arn acs:ram::<uid>:role/<role-name> --access-key-id <id> --access-key-secret <secret>
`,
			MinArgs: 0,
			MaxArgs: 0,
			Discovery: []string{
				resources.DiscoveryAuto,
				resources.DiscoveryAll,
				resources.DiscoveryAccounts,
				resources.DiscoveryK8sClusters,
				resources.DiscoveryAlbs,
				resources.DiscoveryNlbs,
				resources.DiscoveryVpcs,
				resources.DiscoveryWaf,
				resources.DiscoveryCloudFirewall,
				resources.DiscoveryOssBuckets,
				resources.DiscoveryRdsInstances,
			},
			Flags: []plugin.Flag{
				{
					Long:    "access-key-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Alibaba Cloud AccessKey ID",
				},
				{
					Long:    "access-key-secret",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Alibaba Cloud AccessKey secret",
				},
				{
					Long:    "sts-token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "STS security token, for temporary credentials",
				},
				{
					Long:    "role-arn",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "RAM role ARN to assume (acs:ram::<uid>:role/<name>)",
				},
				{
					Long:    "role-session-name",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Session name to use when assuming a RAM role",
				},
				{
					Long:    "region",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Default region for account resolution (e.g. cn-hangzhou)",
				},
				{
					Long:    "regions",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Comma-separated list of regions to scan (default: all enabled regions)",
				},
				{
					Long:    "filters",
					Type:    plugin.FlagType_KeyValue,
					Default: "",
					Desc:    "Filter discovered assets, e.g., --filters regions=cn-hangzhou,ap-southeast-1 --filters exclude:regions=cn-beijing --filters tag:Environment=production --filters exclude:tag:Environment=dev",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=alicloud"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"account": nil,
			},
		},
	},
	Platforms: connection.Platforms,
}

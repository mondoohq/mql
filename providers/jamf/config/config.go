// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/jamf/connection"
	"go.mondoo.com/mql/providers/jamf/provider"
)

var Config = plugin.Provider{
	Name: "jamf",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "jamf",
	ID:      "go.mondoo.com/mql/providers/jamf",
	Version: "13.1.17",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.17"},
	},
	ConnectionTypes: []string{provider.ConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "jamf",
			Use:   "jamf",
			Short: "a Jamf Pro account",
			Long: `Use the Jamf provider to query a Jamf Pro instance.

To access the Jamf Pro API, you need your instance domain and API credentials.

Examples:
  mql shell jamf --client-id <your-client-id> --client-secret <your-client-secret> --instance-domain https://yourdomain.jamfcloud.com
  cnspec scan jamf --client-id <your-client-id> --client-secret <your-client-secret> --instance-domain https://yourdomain.jamfcloud.com
`,
			Flags: []plugin.Flag{
				{
					Long:    "client-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Jamf Pro API client ID",
				},
				{
					Long:        "client-secret",
					Type:        plugin.FlagType_String,
					Default:     "",
					Desc:        "Jamf Pro API client secret",
					Option:      plugin.FlagOption_Password,
					ConfigEntry: "-",
				},
				{
					Long:    "instance-domain",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Jamf Pro domain (e.g., https://yourdomain.jamfcloud.com)",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=jamf"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"api": nil,
			},
		},
	},
}

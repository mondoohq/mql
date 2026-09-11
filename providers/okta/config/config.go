// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/connection"
	"go.mondoo.com/mql/providers/okta/provider"
)

var Config = plugin.Provider{
	Name: "okta",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "okta",
	ID:      "go.mondoo.com/mql/providers/okta",
	Version: "13.6.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.6.1"},
	},
	ConnectionTypes: []string{provider.ConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "okta",
			Use:   "okta",
			Short: "an Okta organization",
			Long: `Use the okta provider to query resources in an Okta organization.

To query an Okta organization, you need the organization's domain and credentials to access that domain. To learn how, read https://mondoo.com/docs/cnspec/identity/okta.

There are two ways to authenticate. An API token is the simplest, but it inherits the privileges of the admin who created it. A service application authenticates with a private key JWT and holds only the scopes it was granted, so it can be limited to read-only access.

Examples:
  cnspec shell okta -organization <okta-domain> -token <api-token>
	cnspec scan okta -organization <okta-domain> -token <api-token>
	cnspec scan okta -organization <okta-domain> -client-id <client-id> -private-key <pem-or-path> -private-key-id <key-id> -scopes okta.users.read,okta.groups.read
`,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "organization",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "The domain of the Okta organization to scan",
				},
				{
					Long:    "token",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Access token for the Okta organization",
				},
				{
					Long:    "client-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Client ID of the Okta service app to authenticate as",
				},
				{
					Long:    "private-key",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Private key of the Okta service app, either the PEM itself or a path to it",
				},
				{
					Long:    "private-key-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "ID of the public key registered with the Okta service app",
				},
				{
					Long:    "scopes",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Okta API scopes to request for the service app, separated by commas",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=okta"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"org": nil,
			},
		},
	},
}

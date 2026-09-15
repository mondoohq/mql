// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/google-workspace/provider"
)

var Config = plugin.Provider{
	Name:            "google-workspace",
	ID:              "go.mondoo.com/cnquery/v9/providers/google-workspace",
	Version:         "13.3.5",
	ConnectionTypes: []string{provider.ConnectionType},
	Platforms:       provider.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "google-workspace",
			Use:   "google-workspace [--credentials-path <credentials-path>] [--customer-id <customer-id>] [--impersonated-user-email <impersonated-user-email>]",
			Short: "a Google Workspace account",
			Long: `Use the google-workspace provider to query resources in a Google Workspace domain.

Examples:
  cnspec shell google-workspace --customer-id <customer-id>
  cnspec shell google-workspace --credentials-path <credentials-path> --customer-id <customer-id>
  cnspec scan google-workspace --credentials-path <credentials-path> --customer-id <customer-id>

Note:

If you set the GOOGLE_APPLICATION_CREDENTIALS environment variable, you don't need to provide the --credentials-path flag.
`,

			Aliases:   []string{"googleworkspace"},
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "credentials-path",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to the service account credentials file (typically a JSON file) with which to access the APIs",
					Option:  plugin.FlagOption_Required,
				},
				{
					Long:    "customer-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Unique ID of the Google Workspace customer account",
					Option:  plugin.FlagOption_Required,
				},
				{
					Long:    "impersonated-user-email",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Email address of the user to impersonate in the session (This is useful when the user executing the command does not have the necessary permissions, but can impersonate a user who does.)",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=google-workspace"},
			Key:          "customer",
			Values: map[string]*inventory.AssetUrlBranch{
				"*": nil,
			},
		},
	},
}

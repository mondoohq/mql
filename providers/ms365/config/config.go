// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/providers/ms365/provider"
)

var Config = plugin.Provider{
	Name: "ms365",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "microsoft",
	ID:      "go.mondoo.com/mql/providers/ms365",
	Version: "13.12.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.12.1"},
	},
	ConnectionTypes: []string{provider.ConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:    "ms365",
			Use:     "ms365",
			Aliases: []string{"m365"},
			Short:   "a Microsoft 365 tenant",
			Long: `Use the ms365 provider to query resources within Microsoft 365, including organizations, users, roles, SharePoint sites, and more.

Examples:
  cnspec shell ms365 --certificate-path <PATH-TO-YOUR-PEM> --tenant-id <YOUR-TENANT-ID> --client-id <YOUR-CLIENT-ID>
  cnspec scan ms365 --certificate-path <PATH-TO-YOUR-PEM> --tenant-id <YOUR-TENANT-ID> --client-id <YOUR-CLIENT-ID>

Notes:
  If you give cnspec access through the Microsoft 365 API, you can omit the certificate-path, tenant-id, and client-id flags. To learn how, read https://mondoo.com/docs/cnspec/saas/m365#give-cnspec-access.
`,
			MinArgs:   0,
			MaxArgs:   5,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    "tenant-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Directory (tenant) ID of the service principal",
				},
				{
					Long:    "client-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Application (client) ID of the service principal",
				},
				{
					Long:    "organization",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Organization to scan",
				},
				{
					Long:    "sharepoint-url",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Sharepoint URL to scan",
				},
				{
					Long:    "client-secret",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Secret for the application",
				},
				{
					Long:    "certificate-path",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path (in PKCS #12/PFX or PEM format) to the authentication certificate",
				},
				{
					Long:    "certificate-secret",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Passphrase for the authentication certificate file",
				},
				{
					Long:    "auth-method",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Comma-separated sign-in methods to use when no client secret or certificate is given: cli, env, workload-identity, managed-identity (default: try all, in that order)",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=ms365"},
		},
	},
}

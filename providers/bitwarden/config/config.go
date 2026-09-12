// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bitwarden/connection"
	"go.mondoo.com/mql/providers/bitwarden/provider"
)

var Config = plugin.Provider{
	Name: "bitwarden",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "bitwarden",
	ID:      "go.mondoo.com/mql/providers/bitwarden",
	Version: "13.0.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "bitwarden",
			Use:   "bitwarden",
			Short: "a Bitwarden organization",
			Long: fmt.Sprintf(`
Use the bitwarden provider to query the organization governance settings of
a Bitwarden Teams or Enterprise organization: security policies, members,
collections, and groups. This provider reads organization governance only;
it never reads vault item secrets.

Authentication uses an organization API key exchanged via OAuth2
client-credentials:

  cnspec shell bitwarden --client-id organization.<uuid> --client-secret <secret>

You can also use the default environment variables '%s' and '%s' to provide
your credentials, and '%s'/'%s' to point at a self-hosted deployment.
`,
				connection.BITWARDEN_CLIENT_ID_VAR,
				connection.BITWARDEN_CLIENT_SECRET_VAR,
				connection.BITWARDEN_API_URL_VAR,
				connection.BITWARDEN_IDENTITY_URL_VAR,
			),
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    connection.OPTION_CLIENT_ID,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Bitwarden organization client ID (e.g. organization.<uuid>)",
				},
				{
					Long:    connection.OPTION_CLIENT_SECRET,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Bitwarden organization client secret",
				},
				{
					Long:    connection.OPTION_API_URL,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Bitwarden Public API base URL, for self-hosted deployments",
				},
				{
					Long:    connection.OPTION_IDENTITY_URL,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Bitwarden identity token URL, for self-hosted deployments",
				},
			},
		},
	},
	Platforms: connection.Platforms,
}

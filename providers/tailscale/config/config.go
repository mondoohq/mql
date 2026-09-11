// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package config

import (
	"fmt"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/tailscale/connection"
	"go.mondoo.com/mql/providers/tailscale/provider"
)

var Config = plugin.Provider{
	Name: "tailscale",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "tailscale",
	ID:      "go.mondoo.com/mql/providers/tailscale",
	Version: "13.4.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.4.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "tailscale",
			Use:   "tailscale",
			Short: "a Tailscale network",
			// The tailnet organization name. e.g. example.com
			MinArgs: 0,
			MaxArgs: 1,
			Long: fmt.Sprintf(`
Use the tailscale provider to query devices, DNS nameservers, and more information about a Tailscale network,
known as a tailnet.

To authenticate using an API access token:

  cnspec shell tailscale --token <access-token>

To authenticate using an OAuth client:

  cnspec shell tailscale --client-id <id> --client-secret <secret>

You can also use the default environment variables '%s', '%s',
and '%s' to provide your credentials.

If you are using an API access token instead of an OAuth client, use the '%s' variable instead.
`,
				connection.TAILSCALE_OAUTH_CLIENT_ID_VAR,
				connection.TAILSCALE_OAUTH_CLIENT_SECRET_VAR,
				connection.TAILSCALE_TAILNET_VAR,
				connection.TAILSCALE_API_KEY_VAR,
			),
			Discovery: []string{
				connection.DiscoveryAll,
				connection.DiscoveryAuto,
				connection.DiscoveryDevices,
				connection.DiscoveryUsers,
			},
			Flags: []plugin.Flag{
				{
					Long:    connection.OPTION_TOKEN,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Tailscale API access token for authentication",
				},
				{
					Long:    connection.OPTION_BASE_URL,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Base URL for the Tailscale API",
				},
				{
					Long:    connection.OPTION_CLIENT_ID,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Tailscale OAuth client ID for authentication",
				},
				{
					Long:    connection.OPTION_CLIENT_SECRET,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Tailscale OAuth client secret for authentication",
				},
			},
		},
	},
}

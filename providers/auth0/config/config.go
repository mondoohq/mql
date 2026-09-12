// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/auth0/connection"
	"go.mondoo.com/mql/providers/auth0/provider"
)

var Config = plugin.Provider{
	Name: "auth0",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "auth0",
	ID:      "go.mondoo.com/mql/providers/auth0",
	Version: "13.0.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "auth0",
			Use:   "auth0",
			Short: "an Auth0 tenant",
			Long: fmt.Sprintf(`
Use the auth0 provider to query applications, connections, users, roles,
actions, log streams, and attack-protection settings of an Auth0 tenant.

Authentication uses a machine-to-machine (M2M) application's client
credentials:

  cnspec shell auth0 --domain <tenant.us.auth0.com> --client-id <id> --client-secret <secret>

You can also use the default environment variables '%s', '%s',
and '%s' to provide your credentials.
`,
				connection.AUTH0_DOMAIN_VAR,
				connection.AUTH0_CLIENT_ID_VAR,
				connection.AUTH0_CLIENT_SECRET_VAR,
			),
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    connection.OPTION_DOMAIN,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Auth0 tenant domain (e.g. your-tenant.us.auth0.com)",
				},
				{
					Long:    connection.OPTION_CLIENT_ID,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Auth0 machine-to-machine application client ID",
				},
				{
					Long:    connection.OPTION_CLIENT_SECRET,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Auth0 machine-to-machine application client secret",
				},
			},
		},
	},
	Platforms: connection.Platforms,
}

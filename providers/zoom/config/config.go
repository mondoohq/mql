// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/zoom/connection"
	"go.mondoo.com/mql/providers/zoom/provider"
)

var Config = plugin.Provider{
	Name: "zoom",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "zoom",
	ID:      "go.mondoo.com/mql/providers/zoom",
	Version: "13.0.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:  "zoom",
			Use:   "zoom",
			Short: "a Zoom account",
			Long: fmt.Sprintf(`
Use the zoom provider to query the account-level security posture of a Zoom
account: meeting-security defaults, cloud-recording encryption, single
sign-on, users, roles, and groups.

Authentication uses Server-to-Server OAuth (an account ID plus a
Server-to-Server OAuth app's client ID and client secret):

  mql shell zoom --account-id <id> --client-id <id> --client-secret <secret>

You can also use the default environment variables '%s', '%s',
and '%s' to provide your credentials.
`,
				connection.ZOOM_ACCOUNT_ID_VAR,
				connection.ZOOM_CLIENT_ID_VAR,
				connection.ZOOM_CLIENT_SECRET_VAR,
			),
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    connection.OPTION_ACCOUNT_ID,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Zoom account ID",
				},
				{
					Long:    connection.OPTION_CLIENT_ID,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Zoom Server-to-Server OAuth app client ID",
				},
				{
					Long:    connection.OPTION_CLIENT_SECRET,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Zoom Server-to-Server OAuth app client secret",
				},
			},
		},
	},
	Platforms: connection.Platforms,
}

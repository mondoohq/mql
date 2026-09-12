// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/keycloak/connection"
	"go.mondoo.com/mql/providers/keycloak/provider"
)

var Config = plugin.Provider{
	Name: "keycloak",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "keycloak",
	ID:      "go.mondoo.com/mql/providers/keycloak",
	Version: "13.0.1",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.1"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "keycloak",
			Use:   "keycloak",
			Short: "a Keycloak server",
			Long: `Use the keycloak provider to query the realms, clients, roles, groups, users, identity providers and authentication flows of a Keycloak server.

There are two ways to authenticate. An admin user signs in with the password
grant against the admin-cli client, which is the quickest way to try the
provider. A service account on a confidential client uses the client credentials
grant and holds only the roles it was granted, so it can be limited to the view
roles of one realm.

A service account needs the realm-management view roles (view-realm, view-users,
view-clients, view-identity-providers and view-authorization) on every realm it
reads. Reading every realm of a server needs the view-realm role of the
master realm's realm-management client instead.

Examples:
  mql shell keycloak --url https://keycloak.example.com --username admin --password <password>
  mql shell keycloak --url https://keycloak.example.com --realm production --client-id mondoo-scanner --client-secret <secret>
  mql scan keycloak --url https://keycloak.example.com --username admin --password <password> --discover realms

Notes:
  KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET,
  KEYCLOAK_USERNAME and KEYCLOAK_PASSWORD supply the same values as the flags.
  A server installed under a context path keeps that path in the URL, for
  example https://keycloak.example.com/auth.
`,
			Discovery: []string{
				connection.DiscoveryAll,
				connection.DiscoveryAuto,
				connection.DiscoveryRealms,
			},
			Flags: []plugin.Flag{
				{
					Long:    "url",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Base URL of the Keycloak server, for example https://keycloak.example.com",
				},
				{
					Long:    "realm",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Scope the scan to a single realm instead of every realm the credentials can read",
				},
				{
					Long:    "auth-realm",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Realm the token is requested from (defaults to master for a user, or the scanned realm for a service account)",
				},
				{
					Long:    "client-id",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Client the token is requested for (defaults to admin-cli for a user)",
				},
				{
					Long:    "client-secret",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Secret of a confidential client, which selects service account authentication",
				},
				{
					Long:    "username",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Admin user to authenticate as, which selects password authentication",
				},
				{
					Long:    "password",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Password of the admin user",
				},
				{
					Long:    "ca-cert",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Certificate authority to trust for the server certificate, either the PEM itself or a path to it",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=saas", "provider=keycloak"},
			Key:          "host",
			Title:        "Host",
			Values: map[string]*inventory.AssetUrlBranch{
				"*": {
					Key:   "realm",
					Title: "Realm",
					Values: map[string]*inventory.AssetUrlBranch{
						"*": nil,
					},
				},
			},
		},
	},
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/activedirectory/provider"
)

var Config = plugin.Provider{
	Name: "activedirectory",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "activedirectory",
	ID:      "go.mondoo.com/mql/providers/activedirectory",
	Version: "13.1.14",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.14"},
	},
	ConnectionTypes: []string{provider.ConnectionType},
	Platforms:       provider.Platforms,
	Connectors: []plugin.Connector{{
		Name:    "activedirectory",
		Use:     "activedirectory",
		Aliases: []string{"ad"},
		Short:   "an Active Directory domain",
		Long: `Use the activedirectory provider to query Active Directory Domain Services via LDAP.

	Examples:
  cnspec shell activedirectory --dc dc01.corp.local --user admin@corp.local --password <PASSWORD>
  cnspec scan activedirectory --dc dc01.corp.local --user admin@corp.local --password <PASSWORD>
  cnspec shell activedirectory --dc dc01.corp.local --kerberos --user admin@CORP.LOCAL --password <PASSWORD>
  cnspec shell activedirectory --dc dc01.corp.local --kerberos --keytab /etc/krb5.keytab --user admin@CORP.LOCAL
  cnspec shell activedirectory --dc dc01.corp.local --kerberos

	Notes:
  LDAPS (port 636) is the default transport. Use --starttls for LDAP+StartTLS on port 389, or --plain-ldap only for labs that cannot use TLS.
  Kerberos authentication supports keytabs, credential caches, user/password, and on Windows the current logon session when no explicit credentials are supplied.
  When no krb5.conf is found (for example on Windows, which has no /etc/krb5.conf), one is generated automatically from --dc, --domain, and the user's realm; pass --krb5conf to use your own for complex or multi-forest topologies.
`,
		MinArgs:   0,
		MaxArgs:   0,
		Discovery: []string{},
		Flags: []plugin.Flag{
			{Long: "dc", Type: plugin.FlagType_String, Desc: "Domain controller hostname or IP address"},
			{Long: "user", Type: plugin.FlagType_String, Desc: "Username (user@domain.com or DOMAIN\\user for simple bind; user@REALM for Kerberos)"},
			{Long: "password", Type: plugin.FlagType_String, Desc: "Password for LDAP bind or Kerberos AS exchange"},
			{Long: "domain", Type: plugin.FlagType_String, Desc: "Domain DNS name (auto-detected from RootDSE if omitted)"},
			{Long: "base-dn", Type: plugin.FlagType_String, Desc: "Base DN for LDAP searches (auto-detected from RootDSE if omitted)"},
			{Long: "ldaps", Type: plugin.FlagType_Bool, Desc: "Use LDAPS (TLS, port 636). This is the default transport."},
			{Long: "plain-ldap", Type: plugin.FlagType_Bool, Desc: "Use plaintext LDAP on port 389 (explicit opt-in; credentials are exposed without TLS)"},
			{Long: "starttls", Type: plugin.FlagType_Bool, Desc: "Upgrade plain LDAP on port 389 to TLS via StartTLS (mutually exclusive with --ldaps and --plain-ldap)"},
			{Long: "port", Type: plugin.FlagType_Int, Desc: "LDAP port (default: 636 for LDAPS, 389 for StartTLS/plain LDAP)"},
			{Long: "insecure", Type: plugin.FlagType_Bool, Desc: "Skip TLS certificate verification"},
			{Long: "kerberos", Type: plugin.FlagType_Bool, Desc: "Use Kerberos/GSSAPI authentication instead of simple bind (on Windows, omit explicit credentials to use the current logon session)"},
			{Long: "keytab", Type: plugin.FlagType_String, Desc: "Path to Kerberos keytab file (requires --kerberos and --user)"},
			{Long: "krb5conf", Type: plugin.FlagType_String, Desc: "Path to krb5.conf (defaults to KRB5_CONFIG env or /etc/krb5.conf; when none exists, a config is generated from --dc/--domain/--user)"},
			{Long: "ccache", Type: plugin.FlagType_String, Desc: "Path to Kerberos credential cache file (requires --kerberos)"},
			{Long: "backend", Type: plugin.FlagType_String, Default: "ldap", Desc: "Backend to use: ldap (default) or rsat (Windows only, not yet implemented)"},
		},
	}},
	AssetUrlTrees: []*inventory.AssetUrlBranch{{
		PathSegments: []string{"technology=directory-service", "provider=activedirectory"},
	}},
}

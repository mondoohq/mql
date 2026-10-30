// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/azure/connection"
)

// connOpts returns the Options map from the single connection ParseCLI builds,
// failing the test if the response shape is unexpected.
func connOpts(t *testing.T, res *plugin.ParseCLIRes) map[string]string {
	t.Helper()
	require.NotNil(t, res)
	require.NotNil(t, res.Asset)
	require.Len(t, res.Asset.Connections, 1)
	return res.Asset.Connections[0].Options
}

// connFilter returns the Discovery.Filter map from the single connection
// ParseCLI builds. Subscription filters now flow through Discovery.Filter
// (mirroring the AWS provider), not the Options map.
func connFilter(t *testing.T, res *plugin.ParseCLIRes) map[string]string {
	t.Helper()
	require.NotNil(t, res)
	require.NotNil(t, res.Asset)
	require.Len(t, res.Asset.Connections, 1)
	require.NotNil(t, res.Asset.Connections[0].Discover)
	return res.Asset.Connections[0].Discover.Filter
}

// TestParseCLINilFlags is a regression test: the flags map only contains keys
// the CLI actually registered, so absent keys (notably the legacy singular
// "subscription", which is never registered) resolve to a nil *llx.Primitive.
// ParseCLI used to dereference those unconditionally and panic before reaching
// any resource. It must now tolerate missing and explicitly-nil flag values.
func TestParseCLINilFlags(t *testing.T) {
	s := Init()

	t.Run("empty flags map does not panic", func(t *testing.T) {
		var res *plugin.ParseCLIRes
		var err error
		require.NotPanics(t, func() {
			res, err = s.ParseCLI(&plugin.ParseCLIReq{
				Flags: map[string]*llx.Primitive{},
			})
		})
		require.NoError(t, err)
		opts := connOpts(t, res)
		// unset auth flags map to empty strings, not a crash
		assert.Empty(t, opts["tenant-id"])
		assert.Empty(t, opts["client-id"])
		// no subscription of either spelling was provided
		assert.NotContains(t, opts, "subscriptions")
	})

	t.Run("explicitly nil flag value does not panic", func(t *testing.T) {
		require.NotPanics(t, func() {
			_, err := s.ParseCLI(&plugin.ParseCLIReq{
				Flags: map[string]*llx.Primitive{
					"tenant-id":     nil,
					"subscriptions": nil,
				},
			})
			require.NoError(t, err)
		})
	})

	t.Run("nil flags map does not panic", func(t *testing.T) {
		require.NotPanics(t, func() {
			_, err := s.ParseCLI(&plugin.ParseCLIReq{Flags: nil})
			require.NoError(t, err)
		})
	})
}

// TestParseCLISubscriptionFlags checks that both the plural "subscriptions"
// flag and the legacy singular "subscription" key populate the connection's
// Discovery.Filter "subscriptions" entry, and that "subscriptions-exclude"
// flows through. These values are no longer written to Options.
func TestParseCLISubscriptionFlags(t *testing.T) {
	s := Init()

	t.Run("plural subscriptions flag", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"subscriptions": llx.StringPrimitive("sub-a,sub-b"),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "sub-a,sub-b", connFilter(t, res)["subscriptions"])
		// no longer duplicated into Options
		assert.NotContains(t, connOpts(t, res), "subscriptions")
	})

	t.Run("singular subscription flag still honored", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"subscription": llx.StringPrimitive("sub-single"),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "sub-single", connFilter(t, res)["subscriptions"])
	})

	t.Run("subscriptions-exclude flows through", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"subscriptions-exclude": llx.StringPrimitive("sub-x"),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "sub-x", connFilter(t, res)["subscriptions-exclude"])
	})
}

// TestParseCLIFiltersFlag checks the --filters key/value flag as an equivalent
// transport for subscription filters, and the precedence rules when both the
// --filters flag and the dedicated flags are set.
func TestParseCLIFiltersFlag(t *testing.T) {
	s := Init()

	t.Run("filters subscriptions populate Discovery.Filter", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"filters": {Map: map[string]*llx.Primitive{
					"subscriptions":         llx.StringPrimitive("sub-a,sub-b"),
					"subscriptions-exclude": llx.StringPrimitive("sub-x"),
				}},
			},
		})
		require.NoError(t, err)
		f := connFilter(t, res)
		assert.Equal(t, "sub-a,sub-b", f["subscriptions"])
		assert.Equal(t, "sub-x", f["subscriptions-exclude"])
	})

	t.Run("unknown filters keys are ignored", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"filters": {Map: map[string]*llx.Primitive{
					"regions": llx.StringPrimitive("eastus"),
				}},
			},
		})
		require.NoError(t, err)
		assert.NotContains(t, connFilter(t, res), "regions")
	})

	t.Run("dedicated flag overrides its --filters counterpart", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"subscriptions": llx.StringPrimitive("dedicated"),
				"filters": {Map: map[string]*llx.Primitive{
					"subscriptions": llx.StringPrimitive("from-filters"),
				}},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "dedicated", connFilter(t, res)["subscriptions"])
	})

	t.Run("plural subscriptions overrides singular subscription", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"subscription":  llx.StringPrimitive("singular"),
				"subscriptions": llx.StringPrimitive("plural"),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "plural", connFilter(t, res)["subscriptions"])
	})

	t.Run("propagate-subscription-tags passes through --filters", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"filters": {Map: map[string]*llx.Primitive{
					"propagate-subscription-tags": llx.StringPrimitive("true"),
				}},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "true", connFilter(t, res)["propagate-subscription-tags"])
	})

	t.Run("subscription-tag: entries pass through --filters", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"filters": {Map: map[string]*llx.Primitive{
					"subscription-tag:env":  llx.StringPrimitive("prod"),
					"subscription-tag:team": llx.StringPrimitive("payments"),
				}},
			},
		})
		require.NoError(t, err)
		f := connFilter(t, res)
		assert.Equal(t, "prod", f["subscription-tag:env"])
		assert.Equal(t, "payments", f["subscription-tag:team"])
	})
}

// TestParseCLICredentials verifies auth flags produce the expected credential
// and option shape without tripping any nil dereference.
func TestParseCLICredentials(t *testing.T) {
	s := Init()

	t.Run("service principal with client secret", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"tenant-id":     llx.StringPrimitive("tenant-1"),
				"client-id":     llx.StringPrimitive("client-1"),
				"client-secret": llx.StringPrimitive("secret-1"),
				"subscriptions": llx.StringPrimitive("sub-a"),
			},
		})
		require.NoError(t, err)
		opts := connOpts(t, res)
		assert.Equal(t, "tenant-1", opts["tenant-id"])
		assert.Equal(t, "client-1", opts["client-id"])

		creds := res.Asset.Connections[0].Credentials
		require.Len(t, creds, 1)
		assert.Equal(t, vault.CredentialType_password, creds[0].Type)
		assert.Equal(t, []byte("secret-1"), creds[0].Secret)
	})

	t.Run("federated token file sets its option", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"federated-token-file": llx.StringPrimitive("/var/run/token"),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "/var/run/token", connOpts(t, res)[connection.OptionFederatedTokenFile])
	})

	t.Run("no auth flags yields no credentials", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{},
		})
		require.NoError(t, err)
		assert.Empty(t, res.Asset.Connections[0].Credentials)
	})
}

// TestParseCLITagFilters guards the allowlist in parseFlagsToFiltersOpts. Tag
// filters are parsed in the connection layer and applied during discovery, but
// they only ever get there if ParseCLI copies them out of the --filters flag
// first. A key missing from the allowlist is dropped silently: the flag is
// accepted, no error is raised, and discovery behaves as if it were never set.
func TestParseCLITagFilters(t *testing.T) {
	s := Init()

	t.Run("tag and exclude:tag survive the allowlist", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"filters": {Map: map[string]*llx.Primitive{
					"tag:env":          llx.StringPrimitive("prod,staging"),
					"exclude:tag:temp": llx.StringPrimitive("true"),
				}},
			},
		})
		require.NoError(t, err)
		f := connFilter(t, res)
		assert.Equal(t, "prod,staging", f["tag:env"])
		assert.Equal(t, "true", f["exclude:tag:temp"])

		// and they reach the typed filter the discovery code actually reads
		parsed := connection.DiscoveryFiltersFromOpts(f)
		assert.Equal(t, map[string]string{"env": "prod,staging"}, parsed.General.Tags)
		assert.Equal(t, map[string]string{"temp": "true"}, parsed.General.ExcludeTags)
	})

	t.Run("tag filters coexist with subscription filters", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"filters": {Map: map[string]*llx.Primitive{
					"subscriptions":          llx.StringPrimitive("sub-a"),
					"tag:env":                llx.StringPrimitive("prod"),
					"subscription-tag:owner": llx.StringPrimitive("platform"),
				}},
			},
		})
		require.NoError(t, err)
		parsed := connection.DiscoveryFiltersFromOpts(connFilter(t, res))
		assert.Equal(t, []string{"sub-a"}, parsed.Subscriptions.Include)
		assert.Equal(t, map[string]string{"env": "prod"}, parsed.General.Tags)
		// subscription-tag is propagation, not a discovery filter
		assert.Equal(t, map[string]string{"owner": "platform"}, parsed.SubscriptionTags)
		assert.Empty(t, parsed.General.ExcludeTags)
	})
}

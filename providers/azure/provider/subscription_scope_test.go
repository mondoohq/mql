// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azure/connection"
)

func TestSingleSubscriptionFilter(t *testing.T) {
	tests := []struct {
		name    string
		filters map[string]string
		want    string
		wantOk  bool
	}{
		{"no filter", map[string]string{}, "", false},
		{"one subscription", map[string]string{"subscriptions": "sub-a"}, "sub-a", true},
		{"one subscription padded", map[string]string{"subscriptions": " sub-a "}, "sub-a", true},
		// several named subscriptions have no single answer; this stays a
		// discovery-only filter
		{"two subscriptions", map[string]string{"subscriptions": "sub-a,sub-b"}, "", false},
		{"trailing comma", map[string]string{"subscriptions": "sub-a,"}, "sub-a", true},
		{"empty value", map[string]string{"subscriptions": ""}, "", false},
		{"only commas", map[string]string{"subscriptions": ",,"}, "", false},
		{"unrelated filter", map[string]string{"subscriptions-exclude": "sub-a"}, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := singleSubscriptionFilter(tt.filters)
			assert.Equal(t, tt.wantOk, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestParseCLIScopesRootAssetToNamedSubscription is the regression test for the
// phantom asset.
//
// subscription-id was only ever set by discovery (getSubConfig, once per
// discovered subscription). The root asset therefore connected with no
// subscription, so every azure.subscription.* query against it failed with the
// SDK's "parameter subscriptionID cannot be empty" -- one guaranteed broken asset
// on every scan, even when the caller had named the subscription explicitly. Its
// PlatformId also degenerated to ".../subscriptions/" with no id, which is not
// unique across runs.
func TestParseCLIScopesRootAssetToNamedSubscription(t *testing.T) {
	s := &Service{}

	t.Run("named subscription scopes the root asset", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Connector: "azure",
			Flags: map[string]*llx.Primitive{
				"subscription": llx.StringPrimitive("sub-a"),
			},
		})
		require.NoError(t, err)
		require.NotNil(t, res.Asset)
		require.Len(t, res.Asset.Connections, 1)

		conf := res.Asset.Connections[0]
		assert.Equal(t, "sub-a", conf.Options[connection.OptionSubscriptionID],
			"the root asset must carry the subscription the caller named")
		// still a discovery filter, so discovery keeps narrowing to it
		assert.Equal(t, "sub-a", conf.Discover.Filter["subscriptions"])
	})

	t.Run("several subscriptions leave the root asset unscoped", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Connector: "azure",
			Flags: map[string]*llx.Primitive{
				"subscriptions": llx.StringPrimitive("sub-a,sub-b"),
			},
		})
		require.NoError(t, err)
		conf := res.Asset.Connections[0]
		assert.Empty(t, conf.Options[connection.OptionSubscriptionID],
			"there is no single subscription to scope the root asset to")
		assert.Equal(t, "sub-a,sub-b", conf.Discover.Filter["subscriptions"])
	})

	t.Run("no subscription flag", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Connector: "azure",
			Flags:     map[string]*llx.Primitive{},
		})
		require.NoError(t, err)
		conf := res.Asset.Connections[0]
		assert.Empty(t, conf.Options[connection.OptionSubscriptionID])
	})
}

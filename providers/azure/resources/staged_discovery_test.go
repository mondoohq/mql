// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	subscriptions "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azure/connection"
)

func TestDiscoveryStageFor(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *inventory.Config
		wantStage discoveryStage
		wantSub   string
	}{
		{
			name:      "no options at all",
			cfg:       &inventory.Config{},
			wantStage: stageLegacy,
		},
		{
			name: "client that does not set the flag stays on the legacy path",
			cfg: &inventory.Config{Options: map[string]string{
				connection.OptionSubscriptionID: "sub-1",
			}},
			wantStage: stageLegacy,
		},
		{
			name: "staged root connection walks the tenant",
			cfg: &inventory.Config{Options: map[string]string{
				plugin.OptionStagedDiscovery: "true",
			}},
			wantStage: stageTenant,
		},
		{
			// the flag is a presence check, not a truthiness check -- the k8s
			// provider sets it to the empty string
			name: "empty flag value still opts in",
			cfg: &inventory.Config{Options: map[string]string{
				plugin.OptionStagedDiscovery: "",
			}},
			wantStage: stageTenant,
		},
		{
			name: "staged connection scoped to a subscription runs stage 2",
			cfg: &inventory.Config{Options: map[string]string{
				plugin.OptionStagedDiscovery:    "true",
				connection.OptionSubscriptionID: "sub-1",
			}},
			wantStage: stageSubscription,
			wantSub:   "sub-1",
		},
		{
			name: "empty subscription id is not a scope",
			cfg: &inventory.Config{Options: map[string]string{
				plugin.OptionStagedDiscovery:    "true",
				connection.OptionSubscriptionID: "",
			}},
			wantStage: stageTenant,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stage, subId := discoveryStageFor(test.cfg)
			assert.Equal(t, test.wantStage, stage)
			assert.Equal(t, test.wantSub, subId)
		})
	}
}

func stagedRootConfig(targets ...string) *inventory.Config {
	return &inventory.Config{
		Type: "azure",
		Id:   7,
		Options: map[string]string{
			plugin.OptionStagedDiscovery: "true",
			connection.OptionTenantID:    "tenant-1",
		},
		Discover: &inventory.Discovery{Targets: targets},
	}
}

func testSubscription(id string) subscriptions.Subscription {
	return subscriptions.Subscription{
		SubscriptionID: new(id),
		TenantID:       new("tenant-1"),
		DisplayName:    new("sub " + id),
	}
}

// A stage-1 subscription asset has to stay discoverable: the targets it carries
// are the only thing that makes the provider run stage 2 when the client
// connects to it. Stripping them here would end the traversal at the
// subscription and no resource would ever be discovered.
func TestTenantStageAssets_SubscriptionConfigTriggersStage2(t *testing.T) {
	rootConf := stagedRootConfig(DiscoveryAuto)
	subs := []subscriptions.Subscription{testSubscription("sub-1"), testSubscription("sub-2")}

	swcs, assets := tenantStageAssets(rootConf, subs, getDiscoveryTargets(rootConf), connection.DiscoveryFilters{})
	require.Len(t, assets, 2)
	require.Len(t, swcs, 2)

	for i, asset := range assets {
		require.Len(t, asset.Connections, 1)
		cfg := asset.Connections[0]

		stage, subId := discoveryStageFor(cfg)
		assert.Equal(t, stageSubscription, stage, "asset %d should route to stage 2", i)
		assert.Equal(t, *subs[i].SubscriptionID, subId)

		require.NotNil(t, cfg.Discover)
		assert.NotEmpty(t, cfg.Discover.Targets, "targets must survive so stage 2 knows what to look for")
	}
}

// The whole point of the stage boundary: a subscription must not inherit
// another connection's resource cache. Several azure resources read the
// subscription from the connection rather than from their own id, so a shared
// cache would answer with the wrong subscription rather than fail.
func TestTenantStageAssets_SubscriptionsGetTheirOwnCache(t *testing.T) {
	rootConf := stagedRootConfig(DiscoveryAuto)
	subs := []subscriptions.Subscription{testSubscription("sub-1"), testSubscription("sub-2")}

	_, assets := tenantStageAssets(rootConf, subs, getDiscoveryTargets(rootConf), connection.DiscoveryFilters{})

	for _, asset := range assets {
		assert.Zero(t, asset.Connections[0].ParentConnectionId,
			"a subscription must not share a resource cache with anything above it")
	}
}

func TestTenantStageAssets_ScannableWhenSubscriptionsAreTargeted(t *testing.T) {
	tests := []struct {
		name             string
		targets          []string
		wantPlatformIds  bool
		subscriptionName string
	}{
		{name: "auto includes subscriptions", targets: []string{DiscoveryAuto}, wantPlatformIds: true},
		{name: "all includes subscriptions", targets: []string{DiscoveryAll}, wantPlatformIds: true},
		{name: "explicitly targeted", targets: []string{DiscoverySubscriptions}, wantPlatformIds: true},
		{name: "mixed targets keep them scannable", targets: []string{DiscoverySubscriptions, DiscoveryInstancesApi}, wantPlatformIds: true},
		{name: "traversal only", targets: []string{DiscoveryInstancesApi}, wantPlatformIds: false},
		{name: "traversal only, several targets", targets: []string{DiscoveryInstancesApi, DiscoveryKeyVaults}, wantPlatformIds: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rootConf := stagedRootConfig(test.targets...)
			subs := []subscriptions.Subscription{testSubscription("sub-1")}

			_, assets := tenantStageAssets(rootConf, subs, getDiscoveryTargets(rootConf), connection.DiscoveryFilters{})
			require.Len(t, assets, 1)

			if test.wantPlatformIds {
				assert.NotEmpty(t, assets[0].PlatformIds,
					"a targeted subscription must stay scannable")
			} else {
				assert.Empty(t, assets[0].PlatformIds,
					"an untargeted subscription is a traversal node, not an asset to scan")
			}
			// Either way it must still be connectable, or stage 2 never runs.
			require.Len(t, assets[0].Connections, 1)
			stage, _ := discoveryStageFor(assets[0].Connections[0])
			assert.Equal(t, stageSubscription, stage)
		})
	}
}

// Stage 2 hands every asset the subscription connection as its parent. That is
// the fix for the duplicate ARM traffic: the plugin service gives all of them
// the subscription runtime's resource cache, so a subscription-wide list is
// paid for once instead of once per asset.
func TestSubscriptionStageAssetOpts_ShareTheSubscriptionCache(t *testing.T) {
	subConf := &inventory.Config{
		Type: "azure",
		Id:   42,
		Options: map[string]string{
			plugin.OptionStagedDiscovery:    "true",
			connection.OptionSubscriptionID: "sub-1",
			connection.OptionTenantID:       "tenant-1",
		},
		Discover: &inventory.Discovery{Targets: []string{DiscoveryAuto}},
	}

	swc := subWithConfig{
		conf: subConf,
		assetOpts: []inventory.CloneOption{
			inventory.WithoutDiscovery(),
			inventory.WithParentConnectionId(subConf.Id),
		},
	}

	asset := mqlObjectToAsset(mqlObject{
		name: "vault-1",
		azureObject: azureObject{
			id:           "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault-1",
			subscription: "sub-1",
			tenant:       new("tenant-1"),
			location:     "westeurope",
			service:      "keyvault",
			objectType:   "vault",
		},
	}, swc.conf, false, swc.assetOpts...)

	require.NotNil(t, asset)
	require.Len(t, asset.Connections, 1)
	cfg := asset.Connections[0]

	assert.Equal(t, uint32(42), cfg.ParentConnectionId,
		"a resource must share its subscription's resource cache")
	// A leaf that still carried discovery targets would re-run stage 2 for the
	// whole subscription, once per resource.
	assert.Empty(t, cfg.GetDiscover().GetTargets(), "resources are leaves, they discover nothing")
	stage, _ := discoveryStageFor(cfg)
	assert.Equal(t, stageSubscription, stage)
	assert.Equal(t, "sub-1", cfg.Options[connection.OptionSubscriptionID])
}

// The legacy path must keep behaving exactly as it did: no parent connection,
// no discovery on the children.
func TestLegacyAssetOpts_Unchanged(t *testing.T) {
	rootConf := &inventory.Config{
		Type:     "azure",
		Id:       9,
		Options:  map[string]string{},
		Discover: &inventory.Discovery{Targets: []string{DiscoveryAuto}},
	}
	sub := testSubscription("sub-1")

	subConf := getSubConfig(rootConf, sub, inventory.WithoutDiscovery())
	assert.Empty(t, subConf.GetDiscover().GetTargets(), "legacy sub configs do not re-discover")
	assert.Equal(t, "sub-1", subConf.Options[connection.OptionSubscriptionID])
	assert.Equal(t, "tenant-1", subConf.Options[connection.OptionTenantID])

	swc := subWithConfig{
		conf:      subConf,
		assetOpts: []inventory.CloneOption{inventory.WithoutDiscovery()},
	}
	asset := mqlObjectToAsset(mqlObject{
		name: "vault-1",
		azureObject: azureObject{
			id:           "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault-1",
			subscription: "sub-1",
			tenant:       new("tenant-1"),
			location:     "westeurope",
			service:      "keyvault",
			objectType:   "vault",
		},
	}, swc.conf, false, swc.assetOpts...)

	require.NotNil(t, asset)
	require.Len(t, asset.Connections, 1)
	assert.Zero(t, asset.Connections[0].ParentConnectionId,
		"the legacy path never shared a resource cache; it must not start now")
	assert.Empty(t, asset.Connections[0].GetDiscover().GetTargets())
}

// Stage 1 writes the ids stage 2 needs into the connection options, so stage 2
// can rebuild the subscription record without asking ARM for it again.
func TestSubscriptionRecord_FromConnectionOptions(t *testing.T) {
	rootConf := stagedRootConfig(DiscoveryAuto)
	_, assets := tenantStageAssets(rootConf, []subscriptions.Subscription{testSubscription("sub-1")}, getDiscoveryTargets(rootConf), connection.DiscoveryFilters{})
	subConf := assets[0].Connections[0]

	conn := &connection.AzureConnection{}
	sub := subscriptionRecord(conn, subConf, "sub-1", false)

	require.NotNil(t, sub.SubscriptionID)
	assert.Equal(t, "sub-1", *sub.SubscriptionID)
	require.NotNil(t, sub.TenantID)
	assert.Equal(t, "tenant-1", *sub.TenantID)
}

func TestSubscriptionRecord_MissingTenantStaysNil(t *testing.T) {
	cfg := &inventory.Config{Options: map[string]string{
		connection.OptionSubscriptionID: "sub-1",
	}}

	sub := subscriptionRecord(&connection.AzureConnection{}, cfg, "sub-1", false)
	require.NotNil(t, sub.SubscriptionID)
	assert.Equal(t, "sub-1", *sub.SubscriptionID)
	assert.Nil(t, sub.TenantID, "an unknown tenant must stay unknown, not become the empty string")
}

// Stage 1 marks the configs it builds, which tells stage 2 both that the
// subscription asset already exists and that its tags have already been
// resolved. Reaching stage 2 from a command line scoped to one subscription
// means no stage 1 ran and neither is true.
func TestBuiltByTenantStage(t *testing.T) {
	rootConf := stagedRootConfig(DiscoveryAuto)
	_, assets := tenantStageAssets(rootConf, []subscriptions.Subscription{testSubscription("sub-1")}, getDiscoveryTargets(rootConf), connection.DiscoveryFilters{})
	require.Len(t, assets, 1)

	assert.True(t, builtByTenantStage(assets[0].Connections[0]),
		"stage 1 built this config, so it emitted the subscription and read its tags")

	cliScoped := &inventory.Config{Options: map[string]string{
		plugin.OptionStagedDiscovery:    "true",
		connection.OptionSubscriptionID: "sub-1",
	}}
	assert.False(t, builtByTenantStage(cliScoped),
		"a command-line scoped run never went through stage 1")
}

// The bug this guards: a subscription with no tags carries none, so an empty
// set at stage 2 is ambiguous unless the stage-1 marker disambiguates it.
// Without that, every untagged subscription in the tenant costs a GET.
func TestTenantStageAssets_UntaggedSubscriptionNeedsNoFetch(t *testing.T) {
	rootConf := stagedRootConfig(DiscoveryAuto)
	rootConf.Discover.Filter = map[string]string{"propagate-subscription-tags": "true"}
	// No tags at all on this one.
	subs := []subscriptions.Subscription{testSubscription("sub-1")}
	filters := connection.DiscoveryFiltersFromOpts(rootConf.Discover.Filter)

	_, assets := tenantStageAssets(rootConf, subs, getDiscoveryTargets(rootConf), filters)
	require.Len(t, assets, 1)
	cfg := assets[0].Connections[0]

	stage2 := connection.DiscoveryFiltersFromOpts(cfg.GetDiscover().GetFilter())
	require.True(t, stage2.PropagateSubscriptionTags)
	require.Empty(t, stage2.SubscriptionTags, "there were none to carry")

	// The marker is what stops stage 2 reading that empty set as "not fetched yet".
	assert.True(t, builtByTenantStage(cfg),
		"an untagged subscription must still be recognised as resolved by stage 1")
}

// Nothing beyond the ids is needed here, so the record must not be fetched.
func TestSubscriptionRecord_SkipsTheFetchWhenNothingNeedsIt(t *testing.T) {
	cfg := &inventory.Config{Options: map[string]string{
		connection.OptionSubscriptionID: "sub-1",
		connection.OptionTenantID:       "tenant-1",
	}}
	conn := &connection.AzureConnection{
		Filters: connection.DiscoveryFilters{
			PropagateSubscriptionTags: true,
			SubscriptionTags:          map[string]string{"env": "prod"},
		},
	}

	// A fetch here would panic on the nil credential, so reaching the end of
	// this call is the assertion.
	sub := subscriptionRecord(conn, cfg, "sub-1", false)
	require.NotNil(t, sub.SubscriptionID)
	assert.Equal(t, "sub-1", *sub.SubscriptionID)
	assert.Empty(t, sub.Tags)
}

func taggedSubscription(id string, tags map[string]string) subscriptions.Subscription {
	sub := testSubscription(id)
	sub.Tags = map[string]*string{}
	for k, v := range tags {
		sub.Tags[k] = new(v)
	}
	return sub
}

// The subscription list already returns each subscription's tags. Stage 1 hands
// them to stage 2 through the config, so stage 2 never has to spend a GET per
// subscription on a record it would only read the tags off.
func TestTenantStageAssets_CarriesSubscriptionTagsToStage2(t *testing.T) {
	rootConf := stagedRootConfig(DiscoveryAuto)
	// Derived the way the connection derives it, so the flag reaches stage 2
	// the same way it does in production.
	rootConf.Discover.Filter = map[string]string{"propagate-subscription-tags": "true"}
	subs := []subscriptions.Subscription{
		taggedSubscription("sub-1", map[string]string{"env": "prod", "team": "infra"}),
		taggedSubscription("sub-2", map[string]string{"env": "dev"}),
	}
	filters := connection.DiscoveryFiltersFromOpts(rootConf.Discover.Filter)
	require.True(t, filters.PropagateSubscriptionTags)

	_, assets := tenantStageAssets(rootConf, subs, getDiscoveryTargets(rootConf), filters)
	require.Len(t, assets, 2)

	// What stage 2 will see once its connection parses the config.
	stage2Filters := func(a *inventory.Asset) connection.DiscoveryFilters {
		return connection.DiscoveryFiltersFromOpts(a.Connections[0].GetDiscover().GetFilter())
	}

	assert.Equal(t, map[string]string{"env": "prod", "team": "infra"},
		stage2Filters(assets[0]).SubscriptionTags)
	// Each subscription carries only its own tags -- the configs must not share
	// a filter map, or every subscription would inherit the last one's tags.
	assert.Equal(t, map[string]string{"env": "dev"},
		stage2Filters(assets[1]).SubscriptionTags)

	// With the tags already in hand, stage 2 has no reason to fetch the record.
	for _, a := range assets {
		f := stage2Filters(a)
		assert.True(t, f.PropagateSubscriptionTags, "propagation must survive to stage 2")
		assert.False(t, f.PropagateSubscriptionTags && len(f.SubscriptionTags) == 0,
			"stage 2 must not need an extra GetSubscription call")
	}
}

// A caller-supplied override decides the tags, so stage 1 must not overwrite it
// with what ARM reported.
func TestTenantStageAssets_CallerTagOverrideWins(t *testing.T) {
	rootConf := stagedRootConfig(DiscoveryAuto)
	rootConf.Discover.Filter = map[string]string{
		"propagate-subscription-tags":                  "true",
		connection.SubscriptionTagFilterPrefix + "env": "override",
	}
	subs := []subscriptions.Subscription{taggedSubscription("sub-1", map[string]string{"env": "prod"})}
	filters := connection.DiscoveryFiltersFromOpts(rootConf.Discover.Filter)

	_, assets := tenantStageAssets(rootConf, subs, getDiscoveryTargets(rootConf), filters)
	require.Len(t, assets, 1)

	got := connection.DiscoveryFiltersFromOpts(assets[0].Connections[0].GetDiscover().GetFilter())
	assert.Equal(t, map[string]string{"env": "override"}, got.SubscriptionTags)
}

// Propagation is off by default; nothing should be written in that case.
func TestTenantStageAssets_NoTagsCarriedWhenPropagationIsOff(t *testing.T) {
	rootConf := stagedRootConfig(DiscoveryAuto)
	subs := []subscriptions.Subscription{taggedSubscription("sub-1", map[string]string{"env": "prod"})}

	_, assets := tenantStageAssets(rootConf, subs, getDiscoveryTargets(rootConf), connection.DiscoveryFilters{})
	require.Len(t, assets, 1)

	got := connection.DiscoveryFiltersFromOpts(assets[0].Connections[0].GetDiscover().GetFilter())
	assert.Empty(t, got.SubscriptionTags)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	subscriptions "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions/v2"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// A discovered asset keeps the scan's discovery filters, without its
// targets: the tag filters narrow the subscription lists its queries read,
// and under staged discovery it shares its parent's resource cache, so a list
// it fetched without them reached the subscription asset too.
func TestDiscoveredAssetsKeepDiscoveryFilters(t *testing.T) {
	parent := &inventory.Config{
		Id: 7,
		Discover: &inventory.Discovery{
			Targets: []string{DiscoverySubscriptions, DiscoveryAppServiceApps},
			Filter:  map[string]string{"tag:env": "a"},
		},
	}
	sub := subscriptionsSubscription("sub-1")

	for name, swc := range map[string]subWithConfig{
		"legacy": {
			sub:       sub,
			conf:      getSubConfig(parent, sub, inventory.WithoutDiscovery(), inventory.WithFilters()),
			assetOpts: leafAssetOpts(nil),
		},
		"staged": {
			sub:       sub,
			conf:      parent,
			assetOpts: leafAssetOpts(&parent.Id),
		},
	} {
		t.Run(name, func(t *testing.T) {
			app := mqlObjectToAsset(mqlObject{
				name: "app",
				azureObject: azureObject{
					subscription: "sub-1",
					id:           "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/app",
					service:      "app-service",
					objectType:   "app",
				},
			}, swc.conf, false, swc.assetOpts...)
			require.NotNil(t, app)
			conf := app.Connections[0]
			if name == "staged" {
				require.Equal(t, uint32(7), conf.ParentConnectionId)
			}
			require.Equal(t, map[string]string{"tag:env": "a"}, conf.GetDiscover().GetFilter())
			require.Empty(t, conf.GetDiscover().GetTargets(), "a discovered asset discovers nothing itself")
		})
	}
}

func subscriptionsSubscription(id string) subscriptions.Subscription {
	return subscriptions.Subscription{SubscriptionID: new(id), TenantID: new("tenant-1")}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/syncx"
)

func TestSubResourceCacheID(t *testing.T) {
	armID := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/outboundRules/r1"
	empty := ""

	for _, tc := range []struct {
		name       string
		armID      *string
		parentID   string
		collection string
		element    string
		want       string
	}{
		{
			name:  "prefers the ARM id, which is already parent-qualified",
			armID: &armID, parentID: "/lb", collection: "outboundRules", element: "r1",
			want: armID,
		},
		{
			name:  "falls back to a parent-qualified key when the id is nil",
			armID: nil, parentID: "/subscriptions/s/.../loadBalancers/lb", collection: "outboundRules", element: "r1",
			want: "/subscriptions/s/.../loadBalancers/lb/outboundRules/r1",
		},
		{
			name:  "an empty id string is treated as absent, not as a key",
			armID: &empty, parentID: "/lb", collection: "outboundRules", element: "r1",
			want: "/lb/outboundRules/r1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, subResourceCacheID(tc.armID, tc.parentID, tc.collection, tc.element))
		})
	}
}

// TestSubResourceCacheIDSeparatesParents is the property that matters: two
// same-named elements under different parents must never share a key. That is
// the whole failure this helper exists to prevent -- CreateResource returns the
// cached occupant of a key it has already seen, so a shared key makes the second
// element silently render as the first.
func TestSubResourceCacheIDSeparatesParents(t *testing.T) {
	a := subResourceCacheID(nil, "/subscriptions/s/.../loadBalancers/lb-a", "outboundRules", "default")
	b := subResourceCacheID(nil, "/subscriptions/s/.../loadBalancers/lb-b", "outboundRules", "default")
	assert.NotEqual(t, a, b)

	// ...and so must two different collections under one parent, which is the
	// private-endpoint case: privateLinkServiceConnections and
	// manualPrivateLinkServiceConnections can hold the same connection name.
	auto := subResourceCacheID(nil, "/pe", "privateLinkServiceConnections", "conn")
	manual := subResourceCacheID(nil, "/pe", "manualPrivateLinkServiceConnections", "conn")
	assert.NotEqual(t, auto, manual)
}

func cacheIDTestRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

// TestKeyVaultSubResourcesDoNotAlias pins the two Key Vault resources that had
// no cache key at all. Both used to pass only an `id` field, which is an
// ordinary declared field and does not feed __id, and neither has an id()
// method -- so every access policy and every network ACL in a scan resolved to
// the first one created. A vault with no firewall inherited the answer of a
// vault that had one.
func TestKeyVaultSubResourcesDoNotAlias(t *testing.T) {
	t.Run("access policies", func(t *testing.T) {
		runtime := cacheIDTestRuntime()
		mk := func(vaultID, tenantID, objectID string) *mqlAzureSubscriptionKeyVaultServiceVaultAccessPolicy {
			r, err := CreateResource(runtime, "azure.subscription.keyVaultService.vault.accessPolicy",
				map[string]*llx.RawData{
					"__id":                   llx.StringData(vaultID + "/accessPolicies/" + tenantID + "/" + objectID + "/"),
					"id":                     llx.StringData(vaultID + "/accessPolicies/" + objectID),
					"objectId":               llx.StringData(objectID),
					"tenantId":               llx.StringData(tenantID),
					"applicationId":          llx.StringData(""),
					"keyPermissions":         llx.ArrayData([]any{}, types.String),
					"secretPermissions":      llx.ArrayData([]any{}, types.String),
					"certificatePermissions": llx.ArrayData([]any{}, types.String),
					"storagePermissions":     llx.ArrayData([]any{}, types.String),
				})
			require.NoError(t, err)
			return r.(*mqlAzureSubscriptionKeyVaultServiceVaultAccessPolicy)
		}

		// two policies on the same vault
		p1 := mk("/vaults/kv", "tenant", "principal-a")
		p2 := mk("/vaults/kv", "tenant", "principal-b")
		assert.NotEqual(t, p1.MqlID(), p2.MqlID())
		assert.Equal(t, "principal-a", p1.ObjectId.Data)
		assert.Equal(t, "principal-b", p2.ObjectId.Data)

		// the same principal on two different vaults
		p3 := mk("/vaults/kv-other", "tenant", "principal-a")
		assert.NotEqual(t, p1.MqlID(), p3.MqlID())
	})

	t.Run("network acls", func(t *testing.T) {
		runtime := cacheIDTestRuntime()
		mk := func(vaultID, defaultAction string) *mqlAzureSubscriptionKeyVaultServiceVaultNetworkAcls {
			r, err := CreateResource(runtime, "azure.subscription.keyVaultService.vault.networkAcls",
				map[string]*llx.RawData{
					"__id":                    llx.StringData(vaultID + "/networkAcls"),
					"id":                      llx.StringData(vaultID + "/networkAcls"),
					"bypass":                  llx.StringData("AzureServices"),
					"defaultAction":           llx.StringData(defaultAction),
					"ipRules":                 llx.ArrayData([]any{}, types.String),
					"virtualNetworkSubnetIds": llx.ArrayData([]any{}, types.String),
				})
			require.NoError(t, err)
			return r.(*mqlAzureSubscriptionKeyVaultServiceVaultNetworkAcls)
		}

		locked := mk("/vaults/kv-locked", "Deny")
		open := mk("/vaults/kv-open", "Allow")
		assert.NotEqual(t, locked.MqlID(), open.MqlID())
		// the failure this guards: the unfirewalled vault reporting Deny
		assert.Equal(t, "Allow", open.DefaultAction.Data)
	})
}

// TestRouteTablesDoNotAlias covers the network side of the same defect.
func TestRouteTablesDoNotAlias(t *testing.T) {
	runtime := cacheIDTestRuntime()
	mk := func(name string) *mqlAzureSubscriptionNetworkServiceRouteTable {
		id := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/routeTables/" + name
		r, err := CreateResource(runtime, "azure.subscription.networkService.routeTable",
			map[string]*llx.RawData{
				"__id":                       llx.StringData(subResourceCacheID(&id, "/subscriptions/s", "routeTables", name)),
				"id":                         llx.StringData(id),
				"name":                       llx.StringData(name),
				"location":                   llx.StringData("eastus"),
				"tags":                       llx.MapData(map[string]any{}, types.String),
				"type":                       llx.StringData("Microsoft.Network/routeTables"),
				"etag":                       llx.StringData("etag"),
				"disableBgpRoutePropagation": llx.BoolData(false),
				"provisioningState":          llx.StringData("Succeeded"),
				"routes":                     llx.ArrayData([]any{}, types.ResourceLike),
			})
		require.NoError(t, err)
		return r.(*mqlAzureSubscriptionNetworkServiceRouteTable)
	}

	a := mk("rt-a")
	b := mk("rt-b")
	assert.NotEqual(t, a.MqlID(), b.MqlID())
	assert.Equal(t, "rt-a", a.Name.Data)
	assert.Equal(t, "rt-b", b.Name.Data)
}

// TestSubscriptionReferencesDoNotAlias pins the Lighthouse case. A reference
// built from a subscription id alone carried no cache key, because
// azure.subscription.id() reads the `id` field that those args never set -- so
// a delegated role in a managed customer subscription resolved against whatever
// subscription reached the shared empty key first.
func TestSubscriptionReferencesDoNotAlias(t *testing.T) {
	runtime := cacheIDTestRuntime()
	mk := func(subID string) *mqlAzureSubscription {
		r, err := CreateResource(runtime, "azure.subscription", map[string]*llx.RawData{
			"__id":           llx.StringData("/subscriptions/" + subID),
			"subscriptionId": llx.StringData(subID),
		})
		require.NoError(t, err)
		return r.(*mqlAzureSubscription)
	}

	a := mk("11111111-1111-1111-1111-111111111111")
	b := mk("22222222-2222-2222-2222-222222222222")
	assert.NotEqual(t, a.MqlID(), b.MqlID())
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", a.SubscriptionId.Data)
	assert.Equal(t, "22222222-2222-2222-2222-222222222222", b.SubscriptionId.Data)
}

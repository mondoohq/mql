// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSub = "00000000-0000-0000-0000-000000000000"

func TestParsePrivateLinkServiceID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantOk  bool
		wantPLS privateLinkServiceTarget
	}{
		{
			name:   "a private link service id parses",
			id:     "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Network/privateLinkServices/my-pls",
			wantOk: true,
			wantPLS: privateLinkServiceTarget{
				SubscriptionID: testSub,
				ResourceGroup:  "rg1",
				Name:           "my-pls",
			},
		},
		{
			// ARM resource ids are case-insensitive, and the casing a caller
			// sees depends on which API returned the id.
			name:   "casing does not matter",
			id:     "/subscriptions/" + testSub + "/resourcegroups/rg1/providers/microsoft.network/privatelinkservices/my-pls",
			wantOk: true,
			wantPLS: privateLinkServiceTarget{
				SubscriptionID: testSub,
				ResourceGroup:  "rg1",
				Name:           "my-pls",
			},
		},

		// Every case below is a shape privateLinkServiceId actually holds in
		// the field. A private endpoint pointed at a first-party service
		// carries that service's own id, and it is by far the common shape --
		// a Private Link service is what you build to expose your OWN service.
		{
			name: "a storage account target is not a private link service",
			id:   "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/acct",
		},
		{
			name: "a sql server target is not a private link service",
			id:   "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Sql/servers/srv",
		},
		{
			name: "a key vault target is not a private link service",
			id:   "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv",
		},
		{
			name: "a cosmos db target is not a private link service",
			id:   "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.DocumentDB/databaseAccounts/cosmos",
		},
		{
			// The provider gate matters on its own: without it a
			// Microsoft.Network resource that has no privateLinkServices
			// component would still have to be rejected by the component
			// lookup, and any future Microsoft.X/privateLinkServices type
			// would be fetched from the wrong API.
			name: "another network resource is not a private link service",
			id:   "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet",
		},
		{
			// Reading the name out of a child id would return the parent
			// service, quietly reporting the wrong resource rather than
			// nothing.
			name: "a child of a private link service is not the service",
			id:   "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Network/privateLinkServices/my-pls/ipConfigurations/ipc1",
		},
		{
			name: "a subscription-scoped id has no resource group",
			id:   "/subscriptions/" + testSub + "/providers/Microsoft.Network/privateLinkServices/my-pls",
		},
		{name: "empty"},
		{name: "not a resource id at all", id: "my-pls"},
		{name: "uneven components", id: "/subscriptions/" + testSub + "/resourceGroups"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parsePrivateLinkServiceID(tc.id)
			require.Equal(t, tc.wantOk, ok)
			assert.Equal(t, tc.wantPLS, got)
		})
	}
}

// The bug being fixed: the init read the service name straight out of the id
// with Component("privateLinkServices"), which errors on every first-party
// target. That error propagated out of NewResource and failed the whole
// privateEndpoints query, so one storage-backed endpoint took the entire
// collection down. Pin both halves: the old read still fails, and the
// discrimination now used in its place does not.
func TestFirstPartyTargetNoLongerErrors(t *testing.T) {
	storageTarget := "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/acct"

	resourceID, err := ParseResourceID(storageTarget)
	require.NoError(t, err, "a first-party target is a perfectly valid resource id")
	_, err = resourceID.Component("privateLinkServices")
	require.Error(t, err, "reading a service name out of a storage account id must fail -- this is the bug")

	_, ok := parsePrivateLinkServiceID(storageTarget)
	assert.False(t, ok, "the same id must be classified, not fetched")
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

func TestAddressPrefixItemsToDict(t *testing.T) {
	ipPrefix := network.AddressPrefixTypeIPPrefix
	serviceTag := network.AddressPrefixTypeServiceTag

	t.Run("nil slice yields empty", func(t *testing.T) {
		assert.Equal(t, []any{}, addressPrefixItemsToDict(nil))
	})

	t.Run("preserves addressPrefixType and skips nil items", func(t *testing.T) {
		items := []*network.AddressPrefixItem{
			{AddressPrefix: strPtr("10.0.0.0/8"), AddressPrefixType: &ipPrefix},
			nil,
			{AddressPrefix: strPtr("Internet"), AddressPrefixType: &serviceTag},
		}
		assert.Equal(t, []any{
			map[string]any{"addressPrefix": "10.0.0.0/8", "addressPrefixType": "IPPrefix"},
			map[string]any{"addressPrefix": "Internet", "addressPrefixType": "ServiceTag"},
		}, addressPrefixItemsToDict(items))
	})
}

func TestStrPtrsToAny(t *testing.T) {
	t.Run("nil slice yields empty", func(t *testing.T) {
		assert.Equal(t, []any{}, strPtrsToAny(nil))
	})

	t.Run("skips nil elements", func(t *testing.T) {
		assert.Equal(t, []any{"80", "443"}, strPtrsToAny([]*string{strPtr("80"), nil, strPtr("443")}))
	})
}

func TestManagerSecurityGroupIDs(t *testing.T) {
	t.Run("nil slice yields nil", func(t *testing.T) {
		assert.Nil(t, managerSecurityGroupIDs(nil))
	})

	t.Run("skips nil items and nil IDs", func(t *testing.T) {
		items := []*network.ManagerSecurityGroupItem{
			{NetworkGroupID: strPtr("/networkManagers/m/networkGroups/g1")},
			nil,
			{NetworkGroupID: nil},
			{NetworkGroupID: strPtr("/networkManagers/m/networkGroups/g2")},
		}
		assert.Equal(t, []string{
			"/networkManagers/m/networkGroups/g1",
			"/networkManagers/m/networkGroups/g2",
		}, managerSecurityGroupIDs(items))
	})
}

// TestConnectivityConfigurationHubsDict guards the assumption behind
// connectivityConfiguration.hubs: JsonToDictSlice preserves the Hub resourceId
// and resourceType keys.
func TestConnectivityConfigurationHubsDict(t *testing.T) {
	hubs := []*network.Hub{
		{ResourceID: strPtr("/vnets/hub-vnet"), ResourceType: strPtr("Microsoft.Network/virtualNetworks")},
	}
	dicts, err := convert.JsonToDictSlice(hubs)
	require.NoError(t, err)
	require.Len(t, dicts, 1)
	hub, ok := dicts[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "/vnets/hub-vnet", hub["resourceId"])
	assert.Equal(t, "Microsoft.Network/virtualNetworks", hub["resourceType"])
}

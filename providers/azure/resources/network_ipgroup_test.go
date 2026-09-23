// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
)

func TestAzureNetworkSubResourceIDs(t *testing.T) {
	t.Run("nil slice yields nil", func(t *testing.T) {
		assert.Nil(t, azureNetworkSubResourceIDs(nil))
	})

	t.Run("skips nil entries and nil inner IDs", func(t *testing.T) {
		subs := []*network.SubResource{
			{ID: strPtr("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw-a")},
			nil,
			{ID: nil},
			{ID: strPtr("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw-b")},
		}
		got := azureNetworkSubResourceIDs(subs)
		assert.Equal(t, []string{
			"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw-a",
			"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw-b",
		}, got)
	})

	t.Run("all-nil slice yields nil", func(t *testing.T) {
		subs := []*network.SubResource{nil, {ID: nil}}
		assert.Nil(t, azureNetworkSubResourceIDs(subs))
	})
}

func TestAzureStrPtrsToStr(t *testing.T) {
	t.Run("nil slice yields nil", func(t *testing.T) {
		assert.Nil(t, azureStrPtrsToStr(nil))
	})

	t.Run("skips nil elements without panicking", func(t *testing.T) {
		// a nil element is exactly what convert.SliceStrPtrToStr crashes on
		got := azureStrPtrsToStr([]*string{strPtr("/ipGroups/a"), nil, strPtr("/ipGroups/b")})
		assert.Equal(t, []string{"/ipGroups/a", "/ipGroups/b"}, got)
	})

	t.Run("all-nil slice yields nil", func(t *testing.T) {
		assert.Nil(t, azureStrPtrsToStr([]*string{nil, nil}))
	})
}

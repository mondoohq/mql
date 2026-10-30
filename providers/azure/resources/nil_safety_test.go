// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	subscriptions "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// A panic in a provider accessor is unrecoverable: the executor evaluates query
// blocks in goroutines, so it takes down the entire scan rather than the one
// query that triggered it. These tests pin the helpers that stand between a
// sparse ARM response and that outcome.

func TestOrZero(t *testing.T) {
	type props struct {
		Name  *string
		Count int
	}

	name := "set"
	real := &props{Name: &name, Count: 3}
	assert.Same(t, real, orZero(real), "a set pointer is returned unchanged")
	assert.Equal(t, "set", *orZero(real).Name)

	// the case that matters: reading a field off an absent properties block
	assert.NotPanics(t, func() {
		var absent *props
		assert.Nil(t, orZero(absent).Name)
		assert.Equal(t, 0, orZero(absent).Count)
	})
}

func TestNestedResourceIDs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		props any
		key   string
		want  []string
	}{
		{
			name: "reads the ids out of a reference array",
			props: map[string]any{"subnets": []any{
				map[string]any{"id": "/subnets/a"},
				map[string]any{"id": "/subnets/b"},
			}},
			key:  "subnets",
			want: []string{"/subnets/a", "/subnets/b"},
		},
		{
			// populate() drops nil pointers, so a SubResource with no ID
			// marshals without the key at all -- this used to panic on the
			// bare entry["id"].(string)
			name: "an entry with no id is skipped, not asserted",
			props: map[string]any{"subnets": []any{
				map[string]any{"id": "/subnets/a"},
				map[string]any{},
				map[string]any{"id": nil},
				map[string]any{"id": 42},
				"not-an-object",
				nil,
			}},
			key:  "subnets",
			want: []string{"/subnets/a"},
		},
		{"absent key", map[string]any{}, "subnets", nil},
		{"key present but not an array", map[string]any{"subnets": "nope"}, "subnets", nil},
		{"properties not a map", "nope", "subnets", nil},
		{"nil properties", nil, "subnets", nil},
		{"empty array", map[string]any{"subnets": []any{}}, "subnets", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				assert.Equal(t, tc.want, nestedResourceIDs(tc.props, tc.key))
			})
		})
	}
}

// TestSubToAssetTolerandsAbsentDisplayName pins the scan-entry-point crash. ARM
// omits displayName for subscriptions in some states -- deleted, disabled, and
// cross-tenant entries projected in by Lighthouse -- and one such subscription
// in a tenant used to panic before a single asset was returned.
func TestSubToAssetToleratesAbsentDisplayName(t *testing.T) {
	subID := "11111111-1111-1111-1111-111111111111"
	tenantID := "22222222-2222-2222-2222-222222222222"

	t.Run("no display name falls back to the subscription id", func(t *testing.T) {
		var asset *inventory.Asset
		require.NotPanics(t, func() {
			asset = subToAsset(subWithConfig{
				sub:  subscriptions.Subscription{SubscriptionID: &subID, TenantID: &tenantID},
				conf: &inventory.Config{},
			})
		})
		require.NotNil(t, asset)
		assert.Contains(t, asset.Name, subID)
		assert.Equal(t, subID, asset.Labels[SubscriptionLabel])
	})

	t.Run("a display name is used when present", func(t *testing.T) {
		name := "Production"
		asset := subToAsset(subWithConfig{
			sub:  subscriptions.Subscription{SubscriptionID: &subID, TenantID: &tenantID, DisplayName: &name},
			conf: &inventory.Config{},
		})
		require.NotNil(t, asset)
		assert.Equal(t, "Azure subscription Production", asset.Name)
	})
}

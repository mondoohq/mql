// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestDistinctPrincipalIDs(t *testing.T) {
	// Synthetic: role assignment lists repeat a principal once per grant and
	// carry an empty ID for a grant whose principal ARM did not report.
	got := distinctPrincipalIDs([]string{
		"aaa", "bbb", "", "aaa", "BBB", "ccc",
	})
	assert.Equal(t, []string{"aaa", "bbb", "ccc"}, got)

	assert.Empty(t, distinctPrincipalIDs(nil))
	assert.Empty(t, distinctPrincipalIDs([]string{""}))
}

func TestEntraPrincipalID(t *testing.T) {
	// Synthetic: one principal seen from two subscriptions of one scan.
	a := entraPrincipalID("sub-a", "8F3C9A2E-1B4D-4E5F-9A6B-7C8D9E0F1A2B")
	b := entraPrincipalID("sub-b", "8f3c9a2e-1b4d-4e5f-9a6b-7c8d9e0f1a2b")
	assert.NotEqual(t, a, b, "the same principal in two subscriptions must not share a cache entry")
	assert.Equal(t, a, entraPrincipalID("sub-a", "8f3c9a2e-1b4d-4e5f-9a6b-7c8d9e0f1a2b"),
		"the object ID's case must not split one principal into two entries")
}

func TestUserAssignedIdentityByPrincipal(t *testing.T) {
	// Synthetic: two user-assigned identities, one with the principal in upper case.
	a := &mqlAzureSubscriptionManagedIdentity{PrincipalId: setString("11111111-aaaa-4aaa-aaaa-aaaaaaaaaaaa")}
	b := &mqlAzureSubscriptionManagedIdentity{PrincipalId: setString("22222222-BBBB-4BBB-BBBB-BBBBBBBBBBBB")}
	blank := &mqlAzureSubscriptionManagedIdentity{PrincipalId: setString("")}
	list := []any{blank, a, "not-an-identity", b}

	assert.Same(t, b, userAssignedIdentityByPrincipal(list, "22222222-bbbb-4bbb-bbbb-bbbbbbbbbbbb"))
	assert.Same(t, a, userAssignedIdentityByPrincipal(list, "11111111-aaaa-4aaa-aaaa-aaaaaaaaaaaa"))
	assert.Nil(t, userAssignedIdentityByPrincipal(list, "33333333-cccc-4ccc-cccc-cccccccccccc"))
	assert.Nil(t, userAssignedIdentityByPrincipal(list, ""), "an empty principal never matches an identity without one")
}

func TestSystemIdentityOwner(t *testing.T) {
	// Synthetic: a resource with a system-assigned identity, one with only a
	// user-assigned identity (no principal), and one without an identity block.
	withSystem := &mqlAzureSubscriptionResourceIdentity{PrincipalId: setString("44444444-dddd-4ddd-dddd-dddddddddddd")}
	withSystem.cacheOwnerId = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"
	userOnly := &mqlAzureSubscriptionResourceIdentity{PrincipalId: setString("")}
	resources := []any{
		&mqlAzureSubscriptionResource{ResourceIdentity: plugin.TValue[*mqlAzureSubscriptionResourceIdentity]{State: plugin.StateIsSet | plugin.StateIsNull}},
		&mqlAzureSubscriptionResource{ResourceIdentity: plugin.TValue[*mqlAzureSubscriptionResourceIdentity]{Data: userOnly, State: plugin.StateIsSet}},
		&mqlAzureSubscriptionResource{ResourceIdentity: plugin.TValue[*mqlAzureSubscriptionResourceIdentity]{Data: withSystem, State: plugin.StateIsSet}},
	}

	got := systemIdentityOwner(resources, "44444444-DDDD-4DDD-DDDD-DDDDDDDDDDDD")
	if assert.NotNil(t, got) {
		assert.Equal(t, withSystem.cacheOwnerId, got.cacheOwnerId)
	}
	assert.Nil(t, systemIdentityOwner(resources, "55555555-eeee-4eee-eeee-eeeeeeeeeeee"))
	assert.Nil(t, systemIdentityOwner(resources, ""), "an empty principal never matches a resource without a system identity")
}

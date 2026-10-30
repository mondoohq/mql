// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserAssignedLicenseID(t *testing.T) {
	tests := []struct {
		name   string
		userID string
		skuID  string
		want   string
	}{
		{"user and sku", "user-1", "sku-a", "user-1/sku-a"},
		{"empty sku still scoped to the user", "user-1", "", "user-1/"},
		{"empty user still scoped to the sku", "", "sku-a", "/sku-a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, userAssignedLicenseID(tc.userID, tc.skuID))
		})
	}
}

// The defect this key fixes: two users holding the same SKU produced the same
// cache key, so CreateResource returned the first user's resource for the
// second and its disabledPlans were reported for both. Assert the two
// dimensions that must stay independent.
func TestUserAssignedLicenseIDDistinguishesUsersAndSkus(t *testing.T) {
	t.Run("same sku, different users", func(t *testing.T) {
		alice := userAssignedLicenseID("alice", "ENTERPRISEPACK")
		bob := userAssignedLicenseID("bob", "ENTERPRISEPACK")
		assert.NotEqual(t, alice, bob,
			"two users on the same SKU must not share a cache key")
	})

	t.Run("same user, different skus", func(t *testing.T) {
		e3 := userAssignedLicenseID("alice", "ENTERPRISEPACK")
		ems := userAssignedLicenseID("alice", "EMS")
		assert.NotEqual(t, e3, ems,
			"one user's two licenses must not share a cache key")
	})

	t.Run("a whole tenant of shared skus stays distinct", func(t *testing.T) {
		const sku = "ENTERPRISEPACK"
		users := []string{"alice", "bob", "carol", "dave", "erin"}
		seen := map[string]bool{}
		for _, u := range users {
			key := userAssignedLicenseID(u, sku)
			assert.False(t, seen[key], "duplicate cache key %q", key)
			seen[key] = true
		}
		assert.Len(t, seen, len(users))
	})

	t.Run("the key is stable for the same pair", func(t *testing.T) {
		assert.Equal(t,
			userAssignedLicenseID("alice", "ENTERPRISEPACK"),
			userAssignedLicenseID("alice", "ENTERPRISEPACK"),
			"the same user and SKU must resolve to one cached resource")
	})
}

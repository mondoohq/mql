// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/compute/v1"
)

func TestHierarchicalFirewallPolicyAssociations(t *testing.T) {
	t.Run("no associations is an empty list", func(t *testing.T) {
		assert.Equal(t, []any{}, hierarchicalFirewallPolicyAssociations(nil))
	})

	t.Run("maps every key and skips nil entries", func(t *testing.T) {
		got := hierarchicalFirewallPolicyAssociations([]*compute.FirewallPolicyAssociation{
			nil,
			{
				Name:             "org-assoc",
				AttachmentTarget: "organizations/123",
				FirewallPolicyId: "456",
				ShortName:        "baseline",
				DisplayName:      "baseline",
				Priority:         10,
			},
		})
		assert.Equal(t, []any{map[string]any{
			"name":             "org-assoc",
			"attachmentTarget": "organizations/123",
			"firewallPolicyId": "456",
			"shortName":        "baseline",
			"displayName":      "baseline",
			"priority":         int64(10),
		}}, got)
	})

	// 1 is the highest valid priority, so 0 means the API reported none.
	t.Run("unreported priority is null", func(t *testing.T) {
		got := hierarchicalFirewallPolicyAssociations([]*compute.FirewallPolicyAssociation{{Name: "a"}})
		if assert.Len(t, got, 1) {
			m := got[0].(map[string]any)
			assert.Contains(t, m, "priority")
			assert.Nil(t, m["priority"])
		}
	})
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
)

func TestNspAccessRuleFields(t *testing.T) {
	t.Run("nil props returns empty values, no panic", func(t *testing.T) {
		dir, state, prefixes, fqdns, subs, tags, emails := nspAccessRuleFields(nil)
		assert.Empty(t, dir)
		assert.Empty(t, state)
		assert.Equal(t, []any{}, prefixes)
		assert.Equal(t, []any{}, fqdns)
		assert.Equal(t, []any{}, subs)
		assert.Equal(t, []any{}, tags)
		assert.Equal(t, []any{}, emails)
	})

	t.Run("inbound rule surfaces prefixes, service tags, and subscription IDs", func(t *testing.T) {
		dir := network.AccessRuleDirectionInbound
		state := network.NspProvisioningStateSucceeded
		props := &network.NspAccessRuleProperties{
			Direction:         &dir,
			ProvisioningState: &state,
			AddressPrefixes:   []*string{new("10.0.0.0/8"), new("192.168.0.0/16")},
			ServiceTags:       []*string{new("AzureCloud")},
			Subscriptions: []*network.SubscriptionID{
				{ID: new("/subscriptions/sub-a")},
				nil,       // must be skipped, not panic
				{ID: nil}, // nil inner ID must be skipped
				{ID: new("/subscriptions/sub-b")},
			},
		}
		gotDir, gotState, prefixes, fqdns, subs, tags, emails := nspAccessRuleFields(props)
		assert.Equal(t, "Inbound", gotDir)
		assert.Equal(t, "Succeeded", gotState)
		assert.Equal(t, []any{"10.0.0.0/8", "192.168.0.0/16"}, prefixes)
		assert.Equal(t, []any{"AzureCloud"}, tags)
		// only the two non-nil IDs survive, in order
		assert.Equal(t, []any{"/subscriptions/sub-a", "/subscriptions/sub-b"}, subs)
		assert.Empty(t, fqdns)
		assert.Empty(t, emails)
	})

	t.Run("outbound rule surfaces FQDNs and email addresses", func(t *testing.T) {
		dir := network.AccessRuleDirectionOutbound
		props := &network.NspAccessRuleProperties{
			Direction:                 &dir,
			FullyQualifiedDomainNames: []*string{new("api.example.com")},
			EmailAddresses:            []*string{new("ops@example.com")},
		}
		gotDir, _, _, fqdns, _, _, emails := nspAccessRuleFields(props)
		assert.Equal(t, "Outbound", gotDir)
		assert.Equal(t, []any{"api.example.com"}, fqdns)
		assert.Equal(t, []any{"ops@example.com"}, emails)
	})
}

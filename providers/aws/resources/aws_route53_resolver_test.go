// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	resolvertypes "github.com/aws/aws-sdk-go-v2/service/route53resolver/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: AutoAllowlist rule type shapes; no target showed this.
func TestFirewallRuleTypeToDictAutoAllowlist(t *testing.T) {
	t.Run("all members set", func(t *testing.T) {
		got := firewallRuleTypeToDict(&resolvertypes.FirewallRuleType{
			AutoAllowlist: &resolvertypes.AutoAllowlistConfig{
				InitialDataTimeframeHours:         aws.Int32(72),
				AutoAllowlistFirewallDomainListId: aws.String("rslvr-fdl-managed"),
				ImportFromFirewallDomainListId:    aws.String("rslvr-fdl-source"),
			},
		})
		require.NotNil(t, got)
		aa, ok := got.(map[string]any)["autoAllowlist"].(map[string]any)
		require.True(t, ok, "autoAllowlist must be a dict")
		assert.Equal(t, int64(72), aa["initialDataTimeframeHours"])
		assert.Equal(t, "rslvr-fdl-managed", aa["autoAllowlistFirewallDomainListId"])
		assert.Equal(t, "rslvr-fdl-source", aa["importFromFirewallDomainListId"])
	})

	t.Run("no import source reads null, not empty", func(t *testing.T) {
		got := firewallRuleTypeToDict(&resolvertypes.FirewallRuleType{
			AutoAllowlist: &resolvertypes.AutoAllowlistConfig{
				AutoAllowlistFirewallDomainListId: aws.String("rslvr-fdl-managed"),
			},
		})
		aa := got.(map[string]any)["autoAllowlist"].(map[string]any)
		assert.Contains(t, aa, "importFromFirewallDomainListId")
		assert.Nil(t, aa["importFromFirewallDomainListId"])
		assert.Nil(t, aa["initialDataTimeframeHours"])
	})

	t.Run("other rule types carry no autoAllowlist key", func(t *testing.T) {
		got := firewallRuleTypeToDict(&resolvertypes.FirewallRuleType{
			FirewallAdvancedThreatCategory: &resolvertypes.FirewallAdvancedThreatCategoryConfig{Category: aws.String("PHISHING")},
		})
		assert.NotContains(t, got.(map[string]any), "autoAllowlist")
	})
}

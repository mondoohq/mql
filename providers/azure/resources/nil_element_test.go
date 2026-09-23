// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	monitor "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A panic in a provider accessor is unrecoverable: the executor evaluates query
// blocks in goroutines, so a nil element in one ARM response takes down the
// entire scan rather than the one resource that carried it. Each conversion below
// walked a slice of optional pointers without a guard, and each had a guarded
// sibling walking the same kind of data -- so the guard was an omission, not a
// judgement that the element could not be nil.

// azureSecurityRuleToMql walked Properties.DestinationPortRanges twice: once
// bare, to expand each range into from/to ports, and once with an `if p != nil`
// guard to report the raw strings. The unguarded walk came first.
func TestSecurityRuleTolerateNilPortRange(t *testing.T) {
	rule := network.SecurityRule{
		ID:   strPtr("/subscriptions/sub/…/securityRules/allow-web"),
		Name: strPtr("allow-web"),
		Properties: &network.SecurityRulePropertiesFormat{
			DestinationPortRanges: []*string{strPtr("80"), nil, strPtr("443-8443")},
		},
	}

	var res *mqlAzureSubscriptionNetworkServiceSecurityrule
	require.NotPanics(t, func() {
		var err error
		res, err = azureSecurityRuleToMql(cacheIDTestRuntime(), rule)
		require.NoError(t, err)
	})
	require.NotNil(t, res)

	// The nil is skipped, and the surrounding entries survive it -- dropping the
	// whole rule would be as wrong as crashing.
	assert.Equal(t, []any{"80", "443-8443"}, res.DestinationPortRanges.Data)
	require.Len(t, res.DestinationPortRange.Data, 2, "80, then 443-8443 expanded")
}

func TestSecurityRuleWithNoPortRanges(t *testing.T) {
	require.NotPanics(t, func() {
		res, err := azureSecurityRuleToMql(cacheIDTestRuntime(), network.SecurityRule{
			ID:         strPtr("/subscriptions/sub/…/securityRules/empty"),
			Properties: &network.SecurityRulePropertiesFormat{},
		})
		require.NoError(t, err)
		require.NotNil(t, res)
	})

	// No properties at all, which ARM sends for a rule mid-provision.
	require.NotPanics(t, func() {
		res, err := azureSecurityRuleToMql(cacheIDTestRuntime(), network.SecurityRule{
			ID: strPtr("/subscriptions/sub/…/securityRules/bare"),
		})
		require.NoError(t, err)
		require.NotNil(t, res)
	})
}

// mqlBgpSettingsFromSdk read each peering address's fields with no nil check.
func TestBgpSettingsTolerateNilPeeringAddress(t *testing.T) {
	bgp := &network.BgpSettings{
		Asn: func() *int64 { v := int64(65515); return &v }(),
		BgpPeeringAddresses: []*network.IPConfigurationBgpPeeringAddress{
			{
				IPConfigurationID:    strPtr("/…/ipConfigurations/default"),
				CustomBgpIPAddresses: []*string{strPtr("169.254.21.5")},
			},
			nil,
		},
	}

	var res *mqlAzureSubscriptionNetworkServiceBgpSettings
	require.NotPanics(t, func() {
		var err error
		res, err = mqlBgpSettingsFromSdk(cacheIDTestRuntime(), "/subscriptions/sub/…/virtualNetworkGateways/gw", bgp)
		require.NoError(t, err)
	})
	require.NotNil(t, res)
	assert.Len(t, res.BgpPeeringAddressesConfig.Data, 1, "the nil element is skipped, the real one is kept")
	assert.Equal(t, int64(65515), res.Asn.Data)
}

func TestBgpSettingsWithNoPeeringAddresses(t *testing.T) {
	require.NotPanics(t, func() {
		res, err := mqlBgpSettingsFromSdk(cacheIDTestRuntime(), "/subscriptions/sub/…/virtualNetworkGateways/gw",
			&network.BgpSettings{})
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.Empty(t, res.BgpPeeringAddressesConfig.Data)
	})
}

// The activity-log alert flattening was declared inside the pager loop, which is
// both why it had no nil guards and why nothing could test it. It is now two
// package-level functions.
func TestAlertActionsTolerateNilActionGroup(t *testing.T) {
	actions := &monitor.ActionList{
		ActionGroups: []*monitor.ActivityLogAlertActionGroup{
			{ActionGroupID: strPtr("/…/actionGroups/oncall")},
			nil,
			{ActionGroupID: strPtr("/…/actionGroups/security")},
		},
	}

	var got []mqlAlertAction
	require.NotPanics(t, func() { got = alertActions(actions) })
	require.Len(t, got, 2)
	assert.Equal(t, "/…/actionGroups/oncall", got[0].ActionGroupId)
	assert.Equal(t, "/…/actionGroups/security", got[1].ActionGroupId)

	// Non-nil so a query can assert on length without a null guard.
	assert.NotNil(t, alertActions(nil))
	assert.Empty(t, alertActions(nil))
	assert.Empty(t, alertActions(&monitor.ActionList{}))
}

func TestAlertConditionsTolerateNilAtBothLevels(t *testing.T) {
	condition := &monitor.AlertRuleAllOfCondition{
		AllOf: []*monitor.AlertRuleAnyOfOrLeafCondition{
			{
				Field:  strPtr("category"),
				Equals: strPtr("Administrative"),
			},
			nil,
			{
				AnyOf: []*monitor.AlertRuleLeafCondition{
					{Field: strPtr("operationName"), Equals: strPtr("Microsoft.Sql/servers/write")},
					nil,
				},
			},
		},
	}

	var got []mqlAlertCondition
	require.NotPanics(t, func() { got = alertConditions(condition) })
	require.Len(t, got, 2, "the nil top-level condition is skipped")
	assert.Equal(t, "category", got[0].FieldName)
	assert.Equal(t, "Administrative", got[0].Equals)
	require.Len(t, got[1].AnyOf, 1, "the nil leaf is skipped, the real one is kept")
	assert.Equal(t, "operationName", got[1].AnyOf[0].FieldName)

	assert.NotNil(t, alertConditions(nil))
	assert.Empty(t, alertConditions(nil))
	assert.Empty(t, alertConditions(&monitor.AlertRuleAllOfCondition{}))
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// A query like azure.subscription.cloudDefender.defenderForServers.enabled
// creates the Defender plan resource by its type name, with no arguments. That
// bare resource must be the same object the parent's forServers() /
// forContainers() builds, not a blank one whose fields are never set.
//
// The parent's fields are primed so nothing reaches the network.
func TestBareDefenderPlanResolvesThroughService(t *testing.T) {
	runtime := runtimeForAsset(t, []string{"//platformid.api.mondoo.app/runtime/azure/subscriptions/sub-1"})

	parent, err := CreateResource(runtime, "azure.subscription.cloudDefenderService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData("sub-1"),
	})
	require.NoError(t, err)
	svc := parent.(*mqlAzureSubscriptionCloudDefenderService)

	servers, err := CreateResource(runtime, ResourceAzureSubscriptionCloudDefenderServiceDefenderForServers, map[string]*llx.RawData{
		"__id":        llx.StringData(ResourceAzureSubscriptionCloudDefenderServiceDefenderForServers + "/sub-1"),
		"enabled":     llx.BoolData(true),
		"pricingTier": llx.StringData("Standard"),
	})
	require.NoError(t, err)
	containers, err := CreateResource(runtime, ResourceAzureSubscriptionCloudDefenderServiceDefenderForContainers, map[string]*llx.RawData{
		"__id":        llx.StringData(ResourceAzureSubscriptionCloudDefenderServiceDefenderForContainers + "/sub-1"),
		"enabled":     llx.BoolData(true),
		"pricingTier": llx.StringData("Standard"),
	})
	require.NoError(t, err)
	svc.ForServers = plugin.TValue[*mqlAzureSubscriptionCloudDefenderServiceDefenderForServers]{
		Data: servers.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForServers), State: plugin.StateIsSet,
	}
	svc.ForContainers = plugin.TValue[*mqlAzureSubscriptionCloudDefenderServiceDefenderForContainers]{
		Data: containers.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForContainers), State: plugin.StateIsSet,
	}

	gotServers, err := NewResource(runtime, ResourceAzureSubscriptionCloudDefenderServiceDefenderForServers, map[string]*llx.RawData{})
	require.NoError(t, err)
	require.Same(t, servers, gotServers)
	require.True(t, gotServers.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForServers).GetEnabled().Data)

	gotContainers, err := NewResource(runtime, ResourceAzureSubscriptionCloudDefenderServiceDefenderForContainers, map[string]*llx.RawData{})
	require.NoError(t, err)
	require.Same(t, containers, gotContainers)
	require.Equal(t, "Standard", gotContainers.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForContainers).GetPricingTier().Data)
}

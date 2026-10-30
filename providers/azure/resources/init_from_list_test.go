// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azure/connection"
)

const testVMID = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1"

// computeServiceWithVMs builds the state a scan is in once the subscription's
// VM list has been walked: the service resource in the cache with its vms field
// already resolved. Nothing here touches Azure.
func computeServiceWithVMs(t *testing.T, runtime *plugin.Runtime, ids ...string) []any {
	t.Helper()

	conn := runtime.Connection.(*connection.AzureConnection)
	svcRes, err := NewResource(runtime, ResourceAzureSubscriptionComputeService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	require.NoError(t, err)
	svc := svcRes.(*mqlAzureSubscriptionComputeService)

	vms := make([]any, 0, len(ids))
	for _, id := range ids {
		vm, err := CreateResource(runtime, ResourceAzureSubscriptionComputeServiceVm, map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		require.NoError(t, err)
		vms = append(vms, vm)
	}
	svc.Vms = plugin.TValue[[]any]{Data: vms, State: plugin.StateIsSet}
	return vms
}

// The point of the change: the init hands back the instance the list already
// built rather than fetching that one resource again. A rebuilt instance would
// mean an API call per asset, and would also discard whatever the list had
// already resolved onto it.
func TestInitFromServiceList_ReturnsTheListedInstance(t *testing.T) {
	runtime := runtimeForAsset(t, nil)
	vms := computeServiceWithVMs(t, runtime, testVMID)

	args := map[string]*llx.RawData{"id": llx.StringData(testVMID)}
	gotArgs, res, err := initAzureSubscriptionComputeServiceVm(runtime, args)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Same(t, vms[0], res, "must return the instance from the list, not a fresh one")
	assert.NotNil(t, gotArgs)
}

// The right one out of several, not just the first.
func TestInitFromServiceList_MatchesOnID(t *testing.T) {
	runtime := runtimeForAsset(t, nil)
	other := "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-2"
	vms := computeServiceWithVMs(t, runtime, other, testVMID)

	_, res, err := initAzureSubscriptionComputeServiceVm(runtime,
		map[string]*llx.RawData{"id": llx.StringData(testVMID)})

	require.NoError(t, err)
	assert.Same(t, vms[1], res)
}

// A miss has to be an error. Falling through with (args, nil, nil) would have
// the runtime build the resource from the id alone, leaving every other field
// unset rather than null -- which reaches the client as an untyped null with
// nothing pointing at the cause.
func TestInitFromServiceList_ReportsAMiss(t *testing.T) {
	runtime := runtimeForAsset(t, nil)
	computeServiceWithVMs(t, runtime, testVMID)

	missing := "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/gone"
	args, res, err := initAzureSubscriptionComputeServiceVm(runtime,
		map[string]*llx.RawData{"id": llx.StringData(missing)})

	require.Error(t, err)
	assert.Nil(t, res)
	assert.Nil(t, args, "returning args would let the runtime build a blank resource")
	assert.Contains(t, err.Error(), "not found")
	assert.Contains(t, err.Error(), missing, "the error should name what was not found")
}

// An empty list is a miss, not a panic or a silent success.
func TestInitFromServiceList_EmptyList(t *testing.T) {
	runtime := runtimeForAsset(t, nil)
	computeServiceWithVMs(t, runtime)

	_, res, err := initAzureSubscriptionComputeServiceVm(runtime,
		map[string]*llx.RawData{"id": llx.StringData(testVMID)})

	require.Error(t, err)
	assert.Nil(t, res)
}

// Callers that already supplied everything must not trigger a list walk.
func TestInitFromServiceList_PassesThroughCompleteArgs(t *testing.T) {
	runtime := runtimeForAsset(t, nil)
	// deliberately no service resource in the cache: reaching the list here
	// would fail, so returning cleanly proves the fast path was taken
	args := map[string]*llx.RawData{
		"id":   llx.StringData(testVMID),
		"name": llx.StringData("vm-1"),
	}

	gotArgs, res, err := initAzureSubscriptionComputeServiceVm(runtime, args)

	require.NoError(t, err)
	assert.Nil(t, res, "the runtime builds the resource itself from complete args")
	assert.Equal(t, args, gotArgs)
}

// A non-string id is a caller error, not something to look up.
func TestInitFromServiceList_RejectsNonStringID(t *testing.T) {
	runtime := runtimeForAsset(t, nil)
	computeServiceWithVMs(t, runtime, testVMID)

	_, res, err := initAzureSubscriptionComputeServiceVm(runtime,
		map[string]*llx.RawData{"id": llx.IntData(42)})

	require.Error(t, err)
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "id must be a non-nil string value")
}

// ARM does not agree with itself on the casing of the type segment: the generic
// resources listing an asset's platform id comes from returns
// ".../Microsoft.App/containerApps/...", while the service listing matched here
// returns ".../Microsoft.App/containerapps/...". An exact comparison reports a
// container app that plainly exists as not found, and its asset scans as empty.
func TestInitFromServiceList_MatchesIDCaseInsensitively(t *testing.T) {
	listed := "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualmachines/vm-1"
	asset := "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1"

	runtime := runtimeForAsset(t, nil)
	vms := computeServiceWithVMs(t, runtime, listed)

	_, res, err := initAzureSubscriptionComputeServiceVm(runtime,
		map[string]*llx.RawData{"id": llx.StringData(asset)})

	require.NoError(t, err, "casing must not decide whether a resource is found")
	assert.Same(t, vms[0], res)
}

// Case-insensitivity must not turn into matching the wrong resource: only the
// casing may differ, never the path itself.
func TestInitFromServiceList_StillDistinguishesDifferentResources(t *testing.T) {
	runtime := runtimeForAsset(t, nil)
	computeServiceWithVMs(t, runtime,
		"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1")

	_, res, err := initAzureSubscriptionComputeServiceVm(runtime,
		map[string]*llx.RawData{"id": llx.StringData(
			"/subscriptions/sub-1/resourceGroups/other-rg/providers/Microsoft.Compute/virtualMachines/vm-1")})

	require.Error(t, err)
	assert.Nil(t, res)
}

// lookupInServiceList backs typed references rather than assets, so its
// contract differs from initFromServiceList's: a miss returns nil and the
// caller falls back to its own fetch, because a reference may legitimately
// point at something outside this scope.
func TestLookupInServiceList(t *testing.T) {
	computeSvcList := func(s *mqlAzureSubscriptionComputeService) *plugin.TValue[[]any] { return s.GetVms() }

	t.Run("hit returns the listed instance", func(t *testing.T) {
		runtime := runtimeForAsset(t, nil)
		vms := computeServiceWithVMs(t, runtime, testVMID)

		got := lookupInServiceList(runtime, ResourceAzureSubscriptionComputeService, computeSvcList, testVMID)
		assert.Same(t, vms[0], got)
	})

	t.Run("miss returns nil rather than an error", func(t *testing.T) {
		runtime := runtimeForAsset(t, nil)
		computeServiceWithVMs(t, runtime, testVMID)

		gone := "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/gone"
		assert.Nil(t, lookupInServiceList(runtime, ResourceAzureSubscriptionComputeService, computeSvcList, gone))
	})

	t.Run("casing only differences still match", func(t *testing.T) {
		listed := "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualmachines/vm-1"
		runtime := runtimeForAsset(t, nil)
		vms := computeServiceWithVMs(t, runtime, listed)

		got := lookupInServiceList(runtime, ResourceAzureSubscriptionComputeService, computeSvcList, testVMID)
		assert.Same(t, vms[0], got)
	})

	// The list only covers the connection's own subscription. Reporting a
	// cross-subscription reference as absent would send the caller down its
	// fallback anyway, but consulting the list first wastes the walk -- and if
	// two subscriptions ever held the same resource name, would match wrongly.
	t.Run("reference into another subscription is not looked up", func(t *testing.T) {
		runtime := runtimeForAsset(t, nil)
		computeServiceWithVMs(t, runtime, testVMID)

		elsewhere := "/subscriptions/sub-2/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1"
		assert.Nil(t, lookupInServiceList(runtime, ResourceAzureSubscriptionComputeService, computeSvcList, elsewhere))
	})

	t.Run("empty id and unparseable id are misses", func(t *testing.T) {
		runtime := runtimeForAsset(t, nil)
		computeServiceWithVMs(t, runtime, testVMID)

		assert.Nil(t, lookupInServiceList(runtime, ResourceAzureSubscriptionComputeService, computeSvcList, ""))
		assert.Nil(t, lookupInServiceList(runtime, ResourceAzureSubscriptionComputeService, computeSvcList, "not-an-arm-id"))
	})
}

const testSubnetID = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/default"

// The requirement: a referenced resource is fetched once for the scan, and
// every consecutive reference is answered from the cache.
//
// NewResource consults the cache only after the init returns, so an init that
// fetches unconditionally pays per reference and then has its result discarded.
// Reaching the cached instance without building a client is what proves the
// second reference is free -- the fake connection here has no usable
// credential, so a fetch would fail rather than succeed quietly.
func TestCachedResource_SecondReferenceIsFree(t *testing.T) {
	runtime := runtimeForAsset(t, nil)

	// stand in for what the first reference left behind
	first, err := CreateResource(runtime, ResourceAzureSubscriptionNetworkServiceSubnet,
		map[string]*llx.RawData{"id": llx.StringData(testSubnetID)})
	require.NoError(t, err)

	args, res, err := initAzureSubscriptionNetworkServiceSubnet(runtime,
		map[string]*llx.RawData{"id": llx.StringData(testSubnetID)})

	require.NoError(t, err)
	require.NotNil(t, res, "the cached subnet must be returned, not refetched")
	assert.Same(t, first, res)
	assert.NotNil(t, args)
}

// A reference to something nothing has fetched yet must still fall through to
// the fetch rather than reporting it absent.
func TestCachedResource_MissFallsThrough(t *testing.T) {
	runtime := runtimeForAsset(t, nil)
	assert.Nil(t, cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceSubnet, testSubnetID))
	assert.Nil(t, cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceSubnet, ""))
}

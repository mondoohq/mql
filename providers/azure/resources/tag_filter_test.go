// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

const (
	testClusterA = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks-a"
	testClusterB = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks-b"
)

// runtimeWithTagFilters is a runtime whose connection carries the parsed
// --filters tag:... and --filters exclude-tag:... options.
func runtimeWithTagFilters(t *testing.T, include, exclude map[string]string) *plugin.Runtime {
	t.Helper()
	runtime := runtimeForAsset(t, nil)
	conn := runtime.Connection.(*connection.AzureConnection)
	conn.Filters.General.Tags = include
	conn.Filters.General.ExcludeTags = exclude
	return runtime
}

func taggedCluster(t *testing.T, runtime *plugin.Runtime, id string, tags map[string]any) *mqlAzureSubscriptionAksServiceCluster {
	t.Helper()
	res, err := CreateResource(runtime, ResourceAzureSubscriptionAksServiceCluster, map[string]*llx.RawData{
		"id":   llx.StringData(id),
		"tags": llx.MapData(tags, types.String),
	})
	require.NoError(t, err)
	return res.(*mqlAzureSubscriptionAksServiceCluster)
}

// aksServiceWithClusters puts the AKS service in the cache with its clusters
// field resolved the way the lister resolves it: the full list, narrowed by
// keepTagMatches.
func aksServiceWithClusters(t *testing.T, runtime *plugin.Runtime, clusters ...any) []any {
	t.Helper()
	svcRes, err := NewResource(runtime, ResourceAzureSubscriptionAksService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData("sub-1"),
	})
	require.NoError(t, err)
	kept := keepTagMatches(runtime, clusters)
	svcRes.(*mqlAzureSubscriptionAksService).Clusters = plugin.TValue[[]any]{Data: kept, State: plugin.StateIsSet}
	return kept
}

func TestKeepTagMatches(t *testing.T) {
	t.Run("no tag filter keeps every entry", func(t *testing.T) {
		runtime := runtimeWithTagFilters(t, nil, nil)
		a := taggedCluster(t, runtime, testClusterA, map[string]any{"env": "a"})
		b := taggedCluster(t, runtime, testClusterB, map[string]any{"env": "b"})

		assert.Equal(t, []any{a, b}, keepTagMatches(runtime, []any{a, b}))
	})

	t.Run("include filter keeps only matching entries", func(t *testing.T) {
		runtime := runtimeWithTagFilters(t, map[string]string{"env": "a"}, nil)
		a := taggedCluster(t, runtime, testClusterA, map[string]any{"env": "a"})
		b := taggedCluster(t, runtime, testClusterB, map[string]any{"env": "b"})
		untagged := taggedCluster(t, runtime, testClusterB+"-untagged", map[string]any{})

		assert.Equal(t, []any{a}, keepTagMatches(runtime, []any{a, b, untagged}))
	})

	t.Run("exclude filter drops matching entries", func(t *testing.T) {
		runtime := runtimeWithTagFilters(t, nil, map[string]string{"env": "b"})
		a := taggedCluster(t, runtime, testClusterA, map[string]any{"env": "a"})
		b := taggedCluster(t, runtime, testClusterB, map[string]any{"env": "b"})

		assert.Equal(t, []any{a}, keepTagMatches(runtime, []any{a, b}))
	})

	t.Run("dropped entries are remembered by type and case-insensitive id", func(t *testing.T) {
		runtime := runtimeWithTagFilters(t, map[string]string{"env": "a"}, nil)
		a := taggedCluster(t, runtime, testClusterA, map[string]any{"env": "a"})
		b := taggedCluster(t, runtime, testClusterB, map[string]any{"env": "b"})
		keepTagMatches(runtime, []any{a, b})

		assert.Same(t, b, tagFilteredOut(runtime, ResourceAzureSubscriptionAksServiceCluster, strings.ToUpper(testClusterB)))
		assert.Nil(t, tagFilteredOut(runtime, ResourceAzureSubscriptionAksServiceCluster, testClusterA), "a kept entry is not filtered out")
		assert.Nil(t, tagFilteredOut(runtime, ResourceAzureSubscriptionComputeServiceVm, testClusterB), "another resource type with the same id must not match")
		assert.Equal(t, []plugin.Resource{b}, tagFilteredOutOfType(runtime, ResourceAzureSubscriptionAksServiceCluster))
		assert.Empty(t, tagFilteredOutOfType(runtime, ResourceAzureSubscriptionComputeServiceVm))
	})
}

// The cluster asset itself and a reference to a cluster the filter left out
// both resolve; only an id that was never listed is a miss.
func TestInitAksClusterResolvesTagFilteredOutCluster(t *testing.T) {
	runtime := runtimeWithTagFilters(t, map[string]string{"env": "a"}, nil)
	a := taggedCluster(t, runtime, testClusterA, map[string]any{"env": "a"})
	b := taggedCluster(t, runtime, testClusterB, map[string]any{"env": "b"})
	kept := aksServiceWithClusters(t, runtime, a, b)
	require.Equal(t, []any{a}, kept)

	_, res, err := initAzureSubscriptionAksServiceCluster(runtime, map[string]*llx.RawData{"id": llx.StringData(testClusterA)})
	require.NoError(t, err)
	assert.Same(t, a, res)

	_, res, err = initAzureSubscriptionAksServiceCluster(runtime, map[string]*llx.RawData{"id": llx.StringData(testClusterB)})
	require.NoError(t, err)
	assert.Same(t, b, res)

	_, res, err = initAzureSubscriptionAksServiceCluster(runtime, map[string]*llx.RawData{"id": llx.StringData(testClusterB + "-gone")})
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestInitFromServiceListResolvesTagFilteredOutEntry(t *testing.T) {
	runtime := runtimeWithTagFilters(t, map[string]string{"env": "a"}, nil)
	other := "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-b"
	newVM := func(id, env string) any {
		vm, err := CreateResource(runtime, ResourceAzureSubscriptionComputeServiceVm, map[string]*llx.RawData{
			"id":   llx.StringData(id),
			"tags": llx.MapData(map[string]any{"env": env}, types.String),
		})
		require.NoError(t, err)
		return vm
	}
	kept, dropped := newVM(testVMID, "a"), newVM(other, "b")

	conn := runtime.Connection.(*connection.AzureConnection)
	svcRes, err := NewResource(runtime, ResourceAzureSubscriptionComputeService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	require.NoError(t, err)
	svcRes.(*mqlAzureSubscriptionComputeService).Vms = plugin.TValue[[]any]{
		Data:  keepTagMatches(runtime, []any{kept, dropped}),
		State: plugin.StateIsSet,
	}

	_, res, err := initAzureSubscriptionComputeServiceVm(runtime, map[string]*llx.RawData{"id": llx.StringData(other)})
	require.NoError(t, err)
	assert.Same(t, dropped, res)
}

// A discovered asset's runtime shares its parent's resource cache but runs on a
// connection of its own, one without the discovery filters. Its lookups are
// handed the parent's service resources, lists already narrowed, and must still
// resolve what the parent's filter left out.
func TestTagFilteredOutResolvesOnRuntimeSharingTheCache(t *testing.T) {
	parent := runtimeWithTagFilters(t, map[string]string{"env": "a"}, nil)
	a := taggedCluster(t, parent, testClusterA, map[string]any{"env": "a"})
	b := taggedCluster(t, parent, testClusterB, map[string]any{"env": "b"})
	aksServiceWithClusters(t, parent, a, b)

	child := runtimeWithTagFilters(t, nil, nil)
	child.Resources = parent.Resources

	_, res, err := initAzureSubscriptionAksServiceCluster(child, map[string]*llx.RawData{"id": llx.StringData(testClusterB)})
	require.NoError(t, err)
	assert.Same(t, b, res)
}

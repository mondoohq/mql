// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

// newNetworkPolicyTestCluster builds the minimum cluster resource
// networkPolicy() reads: an id and the cached NetworkPolicy config the lister
// stores on it.
func newNetworkPolicyTestCluster(runtime *plugin.Runtime, clusterId string, enabled bool) *mqlGcpProjectGkeServiceCluster {
	c := &mqlGcpProjectGkeServiceCluster{MqlRuntime: runtime}
	c.Id = plugin.TValue[string]{Data: clusterId, State: plugin.StateIsSet}
	c.cacheNetworkPolicyConfig = map[string]any{
		"enabled":  enabled,
		"provider": "CALICO",
	}
	return c
}

// TestGkeNetworkPolicyCacheKeyIsPerCluster pins the identity of a cluster's
// network policy.
//
// gcp.project.gkeService.cluster.networkPolicy declares no id() method, so it
// takes its cache key only from an explicit "__id" argument. Passing the value
// as the public "id" field instead left __id empty for every cluster, and
// CreateResource returns the FIRST resource stored under a key -- so on a
// project with more than one cluster every cluster reported the first
// cluster's network policy, and a cluster with network policy switched off
// read as enabled.
func TestGkeNetworkPolicyCacheKeyIsPerCluster(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}

	a := newNetworkPolicyTestCluster(runtime, "cluster-a", true)
	b := newNetworkPolicyTestCluster(runtime, "cluster-b", false)

	npA, err := a.networkPolicy()
	require.NoError(t, err)
	npB, err := b.networkPolicy()
	require.NoError(t, err)

	assert.NotEqual(t, npA.MqlID(), npB.MqlID(),
		"two clusters must not share a network-policy cache key")
	assert.Equal(t, "cluster-a/networkPolicy", npA.MqlID())
	assert.Equal(t, "cluster-b/networkPolicy", npB.MqlID())

	assert.True(t, npA.Enabled.Data, "cluster-a has network policy enabled")
	assert.False(t, npB.Enabled.Data,
		"cluster-b has network policy disabled and must not inherit cluster-a's answer")
}

// TestGkeNetworkPolicyNullWhenUnconfigured keeps the absent case distinguishable
// from a disabled one: a cluster the API reports no NetworkPolicy for resolves
// to null rather than to a fabricated "disabled" record.
func TestGkeNetworkPolicyNullWhenUnconfigured(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}

	c := &mqlGcpProjectGkeServiceCluster{MqlRuntime: runtime}
	c.Id = plugin.TValue[string]{Data: "cluster-c", State: plugin.StateIsSet}

	np, err := c.networkPolicy()
	require.NoError(t, err)
	assert.Nil(t, np)
	assert.Equal(t, plugin.StateIsNull|plugin.StateIsSet, c.NetworkPolicy.State)
}

func TestGkeNetworkPolicyCacheKey(t *testing.T) {
	assert.Equal(t, "abc/networkPolicy", gkeNetworkPolicyCacheKey("abc"))
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// clusterRole is omitted from the list response for clusters that predate
// cross-region replication. An absent role has to reach MQL as null: an empty
// string would read as a fourth role that is neither PRIMARY, SECONDARY nor
// STANDALONE, and a policy filtering on any of those would silently skip the
// cluster.
func TestRedisClusterRole(t *testing.T) {
	assert.Nil(t, redisClusterRole(""), "an absent role must report null, not an empty string")

	for _, role := range []redis.RedisClusterClusterRoleEnum{
		redis.RedisClusterClusterRolePrimary,
		redis.RedisClusterClusterRoleSecondary,
		redis.RedisClusterClusterRoleStandalone,
	} {
		got := redisClusterRole(role)
		require.NotNil(t, got, role)
		assert.Equal(t, string(role), *got)
	}
}

func TestOciRedisClusterSubnet(t *testing.T) {
	// Measured: two DELETED OCI Cache clusters in us-sanjose-1 (2026-11-23)
	// whose subnets were gone; subnet returned "oci.network.subnet not found".
	listed := &mqlOciNetworkSubnet{Id: plugin.TValue[string]{Data: "ocid1.subnet.oc1..live", State: plugin.StateIsSet}}
	subnets := func() *plugin.TValue[[]any] {
		return &plugin.TValue[[]any]{Data: []any{listed}, State: plugin.StateIsSet}
	}
	failing := func() *plugin.TValue[[]any] {
		return &plugin.TValue[[]any]{Error: errors.New("listing must not be read"), State: plugin.StateIsSet}
	}

	t.Run("active cluster on a listed subnet", func(t *testing.T) {
		var field plugin.TValue[*mqlOciNetworkSubnet]
		got, err := ociRedisClusterSubnet("ACTIVE", subnets, "ocid1.subnet.oc1..live", &field)
		require.NoError(t, err)
		assert.Same(t, listed, got)
	})

	t.Run("subnet no longer exists", func(t *testing.T) {
		var field plugin.TValue[*mqlOciNetworkSubnet]
		got, err := ociRedisClusterSubnet("ACTIVE", subnets, "ocid1.subnet.oc1..gone", &field)
		require.NoError(t, err)
		assert.Nil(t, got)
		assert.True(t, field.IsNull())
	})

	t.Run("deleted cluster", func(t *testing.T) {
		var field plugin.TValue[*mqlOciNetworkSubnet]
		got, err := ociRedisClusterSubnet("DELETED", failing, "ocid1.subnet.oc1..gone", &field)
		require.NoError(t, err)
		assert.Nil(t, got)
		assert.True(t, field.IsNull())
	})

	t.Run("listing fails on a live cluster", func(t *testing.T) {
		var field plugin.TValue[*mqlOciNetworkSubnet]
		_, err := ociRedisClusterSubnet("ACTIVE", failing, "ocid1.subnet.oc1..live", &field)
		assert.Error(t, err)
	})
}

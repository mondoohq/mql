// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
